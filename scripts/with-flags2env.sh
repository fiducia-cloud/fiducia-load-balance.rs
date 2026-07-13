#!/usr/bin/env bash
# Run a command with FIDUCIA_* env vars derived from CLI flags: feeds the flags
# through the pinned flags2env parser (.cli-flags.toml schema) then execs the
# command. Used to invoke the fiducia-region binary.
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
flags=()
while (($#)) && [[ "$1" != "--" ]]; do
  flags+=("$1")
  shift
done
if (($# == 0)); then
  echo "usage: scripts/with-flags2env.sh [flags...] -- command [args...]" >&2
  exit 2
fi
shift
if (($# == 0)); then
  echo "flags2env: command is required after --" >&2
  exit 2
fi

bin="${FLAGS2ENV_BIN:-}"
if [[ -z "$bin" ]]; then
  if [[ -x "$root/vendor/flags-2-env/build/flags2env" ]]; then
    bin="$root/vendor/flags-2-env/build/flags2env"
  elif [[ -x "$root/tools/flags-2-env/build/flags2env" ]]; then
    bin="$root/tools/flags-2-env/build/flags2env"
  elif command -v flags2env >/dev/null 2>&1; then
    bin="$(command -v flags2env)"
  else
    echo "flags2env: build the pinned submodule with 'make -C vendor/flags-2-env all' or set FLAGS2ENV_BIN" >&2
    exit 127
  fi
fi

if ((${#flags[@]})); then
  exports="$("$bin" shell-env --config "$root/.cli-flags.toml" -- "${flags[@]}")"
else
  exports="$("$bin" shell-env --config "$root/.cli-flags.toml" --)"
fi
eval "$exports"
exec "$@"
