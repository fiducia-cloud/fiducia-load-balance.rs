# ─── fiducia-cloud · encrypted environment files ────────────────────────────
#
# SHARED MODULE — byte-identical in every fiducia-cloud repo. Fix it in one
# repo and propagate; do not fork it per repo.
#
#   env/enc/<name>.env.enc   ciphertext — COMMITTED to git
#   env/dec/<name>.env       plaintext  — GITIGNORED, mode 0600
#
# The files are dotenv under the hood, so variable NAMES stay readable in the
# ciphertext and a diff shows exactly which values changed. `.enc` is not a
# format sops auto-detects, so every call states the types explicitly.
#
#   just env-keygen                  once per machine
#   just env-whoami                  your recipient — add it to .sops.yaml
#   just env-decrypt                 enc -> dec, for tools needing a real file
#   just env-edit local              change a value (minimal diff)
#   just env-run prod cargo run      no plaintext ever touches disk
#   just env-check                   fail-closed audit — wire into CI

# So `env-run` receives its command as real argv ($1, $2, …) instead of one
# flattened string — otherwise `just env-run local sh -c 'a b'` loses the quotes.
set positional-arguments := true

_enc := justfile_directory() / "env" / "enc"
_dec := justfile_directory() / "env" / "dec"
_fmt := "--input-type dotenv --output-type dotenv"
_dotenv := "python3 " + justfile_directory() / ".just" / "dotenv.py"

# env/dec is runtime-only and deliberately absent from Git. Every public
# env recipe depends on this bootstrap, including recipes that normally keep
# plaintext in memory, so fresh clones have one filesystem contract.
[private]
_env-dec:
    #!/usr/bin/env bash
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)"
    cd "$root"
    for rel in env env/enc env/dec; do
      [[ ! -L "$rel" ]] || { echo "$rel must not be a symlink" >&2; exit 1; }
      [[ ! -e "$rel" || -d "$rel" ]] || { echo "$rel must be a directory" >&2; exit 1; }
    done
    command -v ores-sops >/dev/null 2>&1 || { echo "ores-sops is required to create env/dec" >&2; exit 1; }
    ores-sops ensure-dec

# List every environment and the variable names it defines (never values).
[group('env')]
env-list: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    files=({{ _enc }}/*.env.enc)
    if [[ ${#files[@]} -eq 0 ]]; then echo "no environments in env/enc/"; exit 0; fi
    for f in "${files[@]}"; do
      name=$(basename "$f" .env.enc)
      # Drop sops' own trailing metadata rows (sops_mac, sops_version, …).
      keys=$(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$f" | tr -d '=' \
             | grep -v '^sops_' | tr '\n' ' ')
      printf '%-12s %s\n' "$name" "$keys"
    done

# Decrypt env/enc/*.env.enc into env/dec/*.env (mode 0600). No args = all.
[group('env')]
env-decrypt *names: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    sel=({{ names }})
    if [[ ${#sel[@]} -eq 0 ]]; then
      for f in {{ _enc }}/*.env.enc; do sel+=("$(basename "$f" .env.enc)"); done
    fi
    if [[ ${#sel[@]} -eq 0 ]]; then echo "nothing to decrypt"; exit 0; fi
    for n in "${sel[@]}"; do
      src={{ _enc }}/"$n".env.enc
      [[ -f $src ]] || { echo "no such environment: $n" >&2; exit 1; }
      out={{ _dec }}/"$n".env
      # Write via a 0600 temp file so plaintext is never briefly world-readable.
      tmp=$(mktemp "{{ _dec }}/.$n.XXXXXX")
      chmod 600 "$tmp"
      sops decrypt {{ _fmt }} "$src" > "$tmp"
      mv -f "$tmp" "$out"
      echo "decrypted  env/dec/$n.env"
    done

# Encrypt env/dec/<name>.env back into env/enc/<name>.env.enc. No args = all.
[group('env')]
env-encrypt *names: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    sel=({{ names }})
    if [[ ${#sel[@]} -eq 0 ]]; then
      for f in {{ _dec }}/*.env; do sel+=("$(basename "$f" .env)"); done
    fi
    if [[ ${#sel[@]} -eq 0 ]]; then echo "nothing in env/dec to encrypt"; exit 0; fi
    mkdir -p {{ _enc }}
    for n in "${sel[@]}"; do
      src={{ _dec }}/"$n".env
      [[ -f $src ]] || { echo "no such plaintext: env/dec/$n.env" >&2; exit 1; }
      dst={{ _enc }}/"$n".env.enc
      if [[ -f $dst ]]; then
        # Drive `sops edit` with a copy-as-editor so sops re-encrypts ONLY the
        # values that actually changed. A plain `sops encrypt` would give every
        # line a fresh IV and churn the whole file on every run.
        # sops runs $EDITOR through `sh -c`, so the path needs shell quoting.
        rc=0
        err=$(EDITOR="cp -f -- $(printf '%q' "$src")" sops edit {{ _fmt }} "$dst" 2>&1) || rc=$?
        # 200 is sops' "file has not changed" — a no-op here, not a failure.
        case $rc in
          0)   echo "encrypted  env/enc/$n.env.enc" ;;
          200) echo "unchanged  env/enc/$n.env.enc" ;;
          *)   printf '%s\n' "$err" >&2; exit "$rc" ;;
        esac
      else
        sops encrypt {{ _fmt }} --filename-override "$dst" "$src" > "$dst"
        echo "encrypted  env/enc/$n.env.enc"
      fi
    done

# Edit an encrypted environment in $EDITOR; plaintext never lands on disk.
[group('env')]
env-edit name: _env-dec
    @sops edit {{ _fmt }} {{ _enc }}/{{ name }}.env.enc

# Create a new empty encrypted environment.
[group('env')]
env-new name: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    dst={{ _enc }}/{{ name }}.env.enc
    [[ -e $dst ]] && { echo "already exists: env/enc/{{ name }}.env.enc" >&2; exit 1; }
    mkdir -p {{ _enc }}
    printf '# %s environment for this repo. Values are encrypted; names are not.\n' {{ name }} \
      | sops encrypt {{ _fmt }} --filename-override "$dst" /dev/stdin > "$dst"
    echo "created  env/enc/{{ name }}.env.enc — populate it with: just env-edit {{ name }}"

# Run a command with <name>'s variables exported. Plaintext never hits disk.
[group('env')]
env-run name +cmd: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    src={{ _enc }}/{{ name }}.env.enc
    [[ -f $src ]] || { echo "no such environment: {{ name }}" >&2; exit 1; }
    # Deliberately NOT `sops exec-env`: it shells out to /bin/sh, and it treats
    # the raw dotenv value as opaque so DQ="hello world" keeps its quotes.
    # .just/dotenv.py applies the ordinary dotenv rules once, so every consumer
    # (here, docker, kubernetes) sees byte-identical values.
    # Plaintext exists only in this process's memory and the child's env.
    eval "$(sops decrypt {{ _fmt }} "$src" | {{ _dotenv }} shell)"
    shift          # drop the environment name; "$@" is now the command
    exec "$@"

# Show which variables differ between env/dec/*.env and the committed ciphertext.
[group('env')]
env-status: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    clean=1
    for f in {{ _enc }}/*.env.enc; do
      n=$(basename "$f" .env.enc); p={{ _dec }}/"$n".env
      if [[ ! -f $p ]]; then printf '%-12s not decrypted locally\n' "$n"; continue; fi
      if diff -q <(sops decrypt {{ _fmt }} "$f") "$p" >/dev/null 2>&1; then
        printf '%-12s in sync\n' "$n"
      else
        clean=0
        # `diff` exits 1 here by definition, and grep exits 1 on no match;
        # neither is an error for us, so keep pipefail from aborting the recipe.
        changed=$( { diff <(sops decrypt {{ _fmt }} "$f") "$p" || true; } \
          | { grep -oE '^[<>] [A-Za-z_][A-Za-z0-9_]*=' || true; } \
          | sed 's/^..//;s/=$//' | sort -u | tr '\n' ' ')
        printf '%-12s MODIFIED locally: %s\n' "$n" "${changed:-<comments/order only>}"
      fi
    done
    [[ $clean -eq 1 ]] || echo $'\nrun `just env-encrypt` to fold those changes into the ciphertext'

# Re-encrypt to match .sops.yaml after adding or removing a recipient.
[group('env')]
env-rekey: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    for f in {{ _enc }}/*.env.enc; do
      sops updatekeys --yes --input-type dotenv "$f"
    done
    echo "recipients synced — commit the result"

# Print this machine's age recipient (public key; safe to share and commit).
[group('env')]
env-whoami: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    for p in "${SOPS_AGE_KEY_FILE:-}" \
             "${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt" \
             "$HOME/Library/Application Support/sops/age/keys.txt"; do
      [[ -n $p && -f $p ]] && { age-keygen -y "$p"; exit 0; }
    done
    echo "no age key found — run: just env-keygen" >&2; exit 1

# Create this machine's age key, once. Never overwrites an existing key.
[group('env')]
env-keygen: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ $OSTYPE == darwin* ]]; then
      dir="$HOME/Library/Application Support/sops/age"
    else
      dir="${XDG_CONFIG_HOME:-$HOME/.config}/sops/age"
    fi
    key="$dir/keys.txt"
    if [[ -f $key ]]; then
      echo "key already exists at $key"; age-keygen -y "$key"; exit 0
    fi
    mkdir -p "$dir" && chmod 700 "$dir"
    age-keygen -o "$key" 2>/dev/null
    chmod 600 "$key"
    echo "created $key"
    echo "add this recipient to .sops.yaml, then ask someone to run \`just env-rekey\`:"
    age-keygen -y "$key"

# Fail-closed audit: no plaintext in git, gitignore intact, ciphertext valid.
[group('env')]
env-check: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    fail=0
    note() { echo "  ✗ $1"; fail=1; }

    echo "tracked files:"
    # Dotenv-shaped secrets: `.env`, `.env.<anything>`, and anything under
    # env/dec/. A file like clusters/x/topology.env is non-secret generated
    # config, not a dotenv secret — it is allowed via a `!` rule in .gitignore
    # and is covered by the force-add check below instead.
    bad=$(git ls-files -z 2>/dev/null | tr '\0' '\n' \
      | grep -E '(^|/)\.env$|(^|/)\.env\.[^/]*$|(^|/)env/dec/' \
      | grep -vE '\.(example|sample|template)$' || true)
    if [[ -n $bad ]]; then note "plaintext env files are tracked:"; echo "$bad" | sed 's/^/      /'
    else echo "  ✓ no dotenv secrets tracked"; fi

    # A tracked file that .gitignore also matches was force-added past the
    # rules — the signature of a leaked secret. Scoped to secret-shaped paths on
    # purpose: repos legitimately track a Cargo.lock or an asset that some other
    # rule ignores, and failing on those would just train people to ignore this
    # check. Negated paths (topology.env) aren't ignored, so they never appear.
    # --no-index is required: without it check-ignore skips tracked files,
    # which are precisely the ones we are looking for here.
    forced=$(git ls-files -z 2>/dev/null | tr '\0' '\n' \
      | git check-ignore --no-index --stdin 2>/dev/null \
      | grep -E '(^|/)env/|\.env$|\.age-?key$|(^|/)keys\.txt$|sops-private' || true)
    if [[ -n $forced ]]; then note "tracked despite .gitignore (force-added?):"; echo "$forced" | sed 's/^/      /'
    else echo "  ✓ nothing force-added past .gitignore"; fi

    echo "staged changes:"
    staged=$(git diff --cached --name-only -z 2>/dev/null | tr '\0' '\n' \
      | grep -E '(^|/)\.env$|(^|/)\.env\.[^/]*$|(^|/)env/dec/' \
      | grep -vE '\.(example|sample|template)$' || true)
    if [[ -n $staged ]]; then note "plaintext env files are staged:"; echo "$staged" | sed 's/^/      /'
    else echo "  ✓ nothing plaintext staged"; fi

    echo "private key material:"
    keys=$(git ls-files -z 2>/dev/null | tr '\0' '\n' \
      | grep -E '\.(agekey|age-key)$|(^|/)keys\.txt$|AGE-SECRET-KEY' || true)
    if [[ -n $keys ]]; then note "possible private keys tracked:"; echo "$keys" | sed 's/^/      /'
    else echo "  ✓ no age private keys tracked"; fi

    echo ".gitignore:"
    for rule in '.env' '*.env' '**/*.env' 'env/dec/'; do
      grep -qxF "$rule" .gitignore 2>/dev/null \
        && echo "  ✓ $rule" || note "missing .gitignore rule: $rule"
    done

    # Key-independent checks first, so this whole recipe is runnable in CI with
    # no age key at all. Handing CI a decryption key just to lint would defeat
    # the point of the audit.
    echo "ciphertext integrity:"
    shopt -s nullglob
    found=0
    for f in env/enc/*.env.enc; do
      found=1
      if ! grep -q 'ENC\[AES256_GCM' "$f"; then
        note "$f is NOT sops-encrypted — it is plaintext in env/enc/"
        continue
      fi
      grep -q '^sops_mac=' "$f" || note "$f has no sops MAC (truncated or hand-edited?)"
      # Every file must keep at least two recipients. With one, losing that key
      # makes the file permanently unreadable — sops has no backdoor.
      r=$(grep -c 'map_recipient' "$f" || true)
      if [[ $r -lt 2 ]]; then
        note "$f has $r recipient(s); needs >= 2 so a lost key is survivable"
      else
        echo "  ✓ $f encrypted, $r recipients"
      fi
    done
    [[ $found -eq 1 ]] || echo "  · no environments yet"

    # Only now, and only if a key is actually present, prove it decrypts.
    keyfile=""
    for p in "${SOPS_AGE_KEY_FILE:-}" \
             "${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt" \
             "$HOME/Library/Application Support/sops/age/keys.txt"; do
      [[ -n $p && -f $p ]] && { keyfile=$p; break; }
    done
    if [[ -z $keyfile && -z ${SOPS_AGE_KEY:-} ]]; then
      echo "  · no age key on this host — skipped decryption (fine in CI)"
    else
      for f in env/enc/*.env.enc; do
        sops decrypt --input-type dotenv --output-type dotenv "$f" >/dev/null 2>&1 \
          && echo "  ✓ $f decrypts with your key" \
          || note "$f does NOT decrypt with your key (ask for a rekey)"
      done
    fi

    [[ $fail -eq 0 ]] && echo $'\nenv-check PASSED' || { echo $'\nenv-check FAILED'; exit 1; }

# Wipe decrypted plaintext from env/dec (regenerate with `just env-decrypt`).
[group('env')]
env-clean: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    n=0
    for f in {{ _dec }}/*.env; do
      # Overwrite before unlinking so the plaintext does not linger in free blocks.
      # NOT `dd ... status=none`: that flag is GNU-only, macOS dd rejects it, and
      # with 2>/dev/null||true the overwrite silently never happened. `head -c`
      # from /dev/zero behaves identically on both.
      head -c "$(wc -c <"$f")" /dev/zero > "$f" 2>/dev/null || true
      rm -f -- "$f"
      n=$((n+1))
    done
    echo "removed $n decrypted file(s) from env/dec/"

# ─── containers ─────────────────────────────────────────────────────────────
#
# Decryption happens at RUN time, never at build time. A secret decrypted during
# `docker build` is written into an image layer and stays there — a later
# `RUN rm` does not remove it, and `--build-arg` is worse still because it lands
# in `docker history`.
#
# Unlike the sonus-auris/ores-sops container pattern, nothing is baked into the
# image here: no sops binary, no ciphertext, no entrypoint script. That is not a
# style preference — `sops exec-env` shells out to /bin/sh in BOTH modes
# (`--same-process` included; measured, it fails on a valid single-word binary
# path), and most fiducia services run on gcr.io/distroless/cc-debian12, which
# has no shell. Decrypting host-side and injecting with --env-file is the only
# form that works on distroless, and it leaves the application as PID 1 so
# SIGTERM reaches it directly and it can drain on `docker stop`.
#
# Trade-off, stated plainly: --env-file values are visible in `docker inspect`.
# The in-image alternative instead exposes SOPS_AGE_KEY there — a key that
# decrypts every environment — so this is the smaller leak, not a free win.
# For real deployments use `env-k8s-secret` (below) or a platform secret store.

# Run a container with <name>'s variables injected. Image needs no sops/shell.
# Everything after <name> goes to `docker run` verbatim, so flags work:
#   just env-docker-run local -p 8080:8080 --name api ghcr.io/…/fiducia-auth:dev
[group('docker')]
env-docker-run name +args: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    src={{ _enc }}/{{ name }}.env.enc
    [[ -f $src ]] || { echo "no such environment: {{ name }}" >&2; exit 1; }
    command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
    shift 1   # drop <name>; "$@" is everything docker run should receive
    # Materialise and validate BEFORE invoking docker. Inlining this as a
    # process substitution fails open: if the pipeline errors, docker still
    # receives a truncated env-file and cheerfully starts the container without
    # its secrets. `set -e` on the assignment turns that into a hard stop.
    envdata=$(sops decrypt {{ _fmt }} "$src" | {{ _dotenv }} envfile)
    # The plaintext is a pipe the docker CLI reads; it never reaches the disk.
    # No --rm here: the caller controls docker's flags, so `-d`, `--rm`, `-p`
    # and friends are theirs to pass.
    exec docker run --env-file <(printf '%s\n' "$envdata") "$@"

# Materialise a 0600 env-file for `docker compose` (env_file:) — plaintext on disk.
[group('docker')]
env-docker-env-file name: _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    src={{ _enc }}/{{ name }}.env.enc
    [[ -f $src ]] || { echo "no such environment: {{ name }}" >&2; exit 1; }
    out={{ _dec }}/{{ name }}.env
    tmp=$(mktemp "{{ _dec }}/.{{ name }}.XXXXXX"); chmod 600 "$tmp"
    sops decrypt {{ _fmt }} "$src" | {{ _dotenv }} envfile > "$tmp"; mv -f "$tmp" "$out"
    # compose needs a real path for `env_file:`; prefer env-docker-run when the
    # plaintext file is avoidable. Wipe it afterwards with `just env-clean`.
    echo "$out"

# Render a Kubernetes Secret from <name>. Pipe to `kubectl apply -f -` to apply.
[group('docker')]
env-k8s-secret name secret="": _env-dec
    #!/usr/bin/env bash
    set -euo pipefail
    src={{ _enc }}/{{ name }}.env.enc
    [[ -f $src ]] || { echo "no such environment: {{ name }}" >&2; exit 1; }
    sname="{{ secret }}"
    if [[ -z $sname ]]; then
      # NOT basename(justfile_directory()): inside a container the repo is mounted
      # at an arbitrary path (/w, /workspace, /github/workspace) and the secret
      # would silently be named after the mount point. The git remote is stable
      # wherever the repo is checked out.
      repo=$(git config --get remote.origin.url 2>/dev/null | sed 's#.*[/:]##; s#\.git$##')
      [[ -n $repo ]] || repo=$(basename "$PWD")
      sname="$(printf '%s-%s' "$repo" "{{ name }}" | tr '._' '--' | tr -cd 'a-zA-Z0-9-')"
    fi
    # --dry-run=client: this only renders YAML, it never contacts a cluster.
    # The app container then uses `envFrom: [secretRef: {name: <sname>}]` and
    # stays distroless — it never needs sops or the age key.
    # Rendered directly rather than via `kubectl --from-env-file`, which is the
    # same dotenv format and so cannot carry a multi-line value either.
    sops decrypt {{ _fmt }} "$src" | {{ _dotenv }} k8s "$sname"

# Report whether this environment can run the env recipes, and which ones.
# The pattern has to work on a laptop, inside a devcontainer, and on a CI runner
# with no key — those have different tools available, so state it rather than
# failing later with something cryptic.
[group('env')]
env-doctor: _env-dec
    #!/usr/bin/env bash
    set -uo pipefail
    ok=0; miss=0
    row() { # name required-for
      if command -v "$1" >/dev/null 2>&1; then
        printf '  ✓ %-10s %s\n' "$1" "$(command -v "$1")"; ok=$((ok+1))
      else
        printf '  ✗ %-10s MISSING — needed for: %s\n' "$1" "$2"; miss=$((miss+1))
      fi
    }
    echo "tools:"
    row bash       "every recipe"
    row git        "env-check"
    row sops       "encrypt/decrypt/edit/rekey"
    row python3    "env-run, env-docker-run, env-k8s-secret (.just/dotenv.py)"
    row age-keygen "env-keygen, env-whoami only"
    row docker     "env-docker-run only"
    row kubectl    "only to APPLY a Secret; env-k8s-secret renders YAML without it"

    echo "key material:"
    key=""
    for p in "${SOPS_AGE_KEY_FILE:-}" \
             "${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt" \
             "$HOME/Library/Application Support/sops/age/keys.txt"; do
      [[ -n $p && -f $p ]] && { key=$p; break; }
    done
    if [[ -n ${SOPS_AGE_KEY:-} ]]; then echo "  ✓ SOPS_AGE_KEY set in the environment"
    elif [[ -n $key ]]; then echo "  ✓ key file $key"
    else echo "  · no age key — read-only checks still work (this is normal in CI)"; fi

    echo "context:"
    # /.dockerenv is created by docker; cgroup matching also catches podman/k8s.
    if [[ -f /.dockerenv ]] || grep -qaE 'docker|containerd|kubepods' /proc/1/cgroup 2>/dev/null; then
      echo "  running INSIDE a container"
    else
      echo "  running on a host (not containerised)"
    fi
    echo "  uname=$(uname -s) arch=$(uname -m)"
    [[ -n ${IN_NIX_SHELL:-} ]] && echo "  nix devshell: $IN_NIX_SHELL" || echo "  nix devshell: no"

    echo
    if [[ $miss -eq 0 ]]; then echo "env-doctor: all tools present"; else
      echo "env-doctor: $ok present, $miss missing — recipes needing the missing tools will fail"; fi
