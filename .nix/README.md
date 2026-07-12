# .nix

Nix flake defining the reproducible development shell for this repo (Rust toolchain
plus supporting tooling).

- `flake.nix` — the `devShells.default` definition.
- `flake.lock` — pinned input revisions (do not hand-edit).

Entered via `nix develop ./.nix`, the repo-root `shell` wrapper, or direnv (`.envrc`).
