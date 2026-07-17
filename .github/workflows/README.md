# workflows

GitHub Actions pipelines for the load balancer.

- `ci.yml` — blocking formatting, clippy, all-target tests, CLI flag-contract,
  and dependency-audit gates on Rust 1.95.0. Sibling interface and routing
  sources are checked out at the immutable revisions documented in the root
  README.
- `docker.yml` — build and publish the non-root container image on pushes to
  `main`, using those same immutable sibling revisions, only the commit-SHA tag,
  maximum provenance, and an SBOM.
- `cli-flags.yml` — audits `.cli-flags.toml` with the pinned `flags2env`
  submodule whenever the CLI flag schema, scripts, or submodule change.

Cluster deployment is intentionally absent and belongs to `fiducia-monorepo`.

## Security baseline

Every executable workflow uses explicit least-privilege permissions, immutable
third-party action or container references, non-persisted checkout credentials,
concurrency control, and a job timeout. The main CI workflow validates this
directory with the digest-pinned actionlint container. Environment mutation is
forbidden unless this README documents a repository-specific platform exception.
