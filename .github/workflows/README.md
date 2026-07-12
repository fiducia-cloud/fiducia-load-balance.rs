# workflows

GitHub Actions pipelines for the load balancer.

- `ci.yml` — build, lint, and test on push and pull request.
- `docker.yml` — build and publish the container image on pushes to `main`.
- `deploy-test.yml` — secret-gated deploy to the `fiducia-test` Kubernetes
  environment (requires the `KUBE_CONFIG_TEST` secret).
