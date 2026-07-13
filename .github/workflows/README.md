# workflows

GitHub Actions pipelines for the load balancer.

- `ci.yml` — blocking formatting, clippy, all-target tests, CLI flag-contract,
  and dependency-audit gates on Rust 1.95.0. Sibling interface and routing
  sources are checked out at the immutable revisions documented in the root
  README.
- `docker.yml` — build and publish the non-root container image on pushes to
  `main`, using those same immutable sibling revisions.
- `deploy-test.yml` — secret-gated deploy to the `fiducia-test` Kubernetes
  environment; `KUBE_CONFIG_TEST` is mandatory, and missing, invalid, or empty
  credentials, a missing target, or an incomplete rollout fail the job.
- `cli-flags.yml` — audits `.cli-flags.toml` with the pinned `flags2env`
  submodule whenever the CLI flag schema, scripts, or submodule change.
