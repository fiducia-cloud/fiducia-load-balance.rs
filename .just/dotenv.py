#!/usr/bin/env python3
"""Normalise a decrypted sops dotenv stream into one target format.

SHARED MODULE — byte-identical in every fiducia-cloud repo, alongside env.just.

Every consumer must agree on what a value *is*, or the same encrypted file
yields different bytes depending on how it was loaded. It reads sops' dotenv
output on stdin and applies the ordinary dotenv rules once:

    "…"   surrounding quotes stripped, \\n \\t \\r \\\\ expanded
    '…'   surrounding quotes stripped, contents literal
    …     literal, spaces and all
    KEY=a=b  split on the FIRST '=' only

Without this, each consumer inherits its loader's quirks: `docker --env-file`
and `kubectl --from-env-file` both keep the surrounding quotes and leave \\n as
two characters, so a PEM arrives as `"-----BEGIN…\\nMII…"` and PKCS#8 parsing
fails. Measured, not assumed.

Modes:
  shell    `export K=<shell-quoted>` — safe to eval
  envfile  `K=V` for docker --env-file. That format is one line per variable
           with no escape processing, so a value containing a newline CANNOT be
           represented: docker keeps the first line and silently drops the rest.
           This mode exits non-zero instead of truncating.
  k8s      a complete v1/Secret with base64 data, which has no such limit and
           carries multi-line values (PEMs) intact.
"""
import base64
import re
import sys

MODES = ("shell", "envfile", "k8s")


def parse(stream):
    out = []
    for line in stream:
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if k.startswith("sops_"):          # sops' own trailing metadata rows
            continue
        if len(v) >= 2 and v[0] == v[-1] == '"':
            # One pass, so `\\n` cannot be re-read as an escape introducer.
            v = v[1:-1].encode().decode("unicode_escape")
        elif len(v) >= 2 and v[0] == v[-1] == "'":
            v = v[1:-1]
        out.append((k, v))
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "shell"
    if mode not in MODES:
        sys.exit("dotenv.py: mode must be one of %s" % ", ".join(MODES))
    name = sys.argv[2] if len(sys.argv) > 2 else "app-env"
    pairs = parse(sys.stdin)

    if mode == "shell":
        for k, v in pairs:
            print("export %s=%s" % (k, "'" + v.replace("'", "'\\''") + "'"))

    elif mode == "envfile":
        bad = [k for k, v in pairs if "\n" in v or "\r" in v]
        if bad:
            sys.exit(
                "dotenv.py: %s contain newlines, which docker --env-file cannot\n"
                "represent — it would keep the first line and drop the rest.\n"
                "Use `just env-run <env> <cmd>` or `just env-k8s-secret <env>`,\n"
                "or store the value single-line (e.g. base64)." % ", ".join(bad))
        for k, v in pairs:
            print("%s=%s" % (k, v))

    elif mode == "k8s":
        print("apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\ntype: Opaque\ndata:" % name)
        for k, v in sorted(pairs):
            print("  %s: %s" % (k, base64.b64encode(v.encode()).decode()))


main()
