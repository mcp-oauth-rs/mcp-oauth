# Contributing

Issues and pull requests are welcome. Please report security problems
privately instead, see [SECURITY.md](SECURITY.md).

Before opening a pull request:

- run `ci/run.sh`: the same jobs as GitHub Actions (format, clippy with
  `-D warnings`, tests, docs, gitleaks over the history, workflow lint);
- add a test for the behaviour you change, and update the README, `docs/` and the
  crate docs in the same commit when behaviour, configuration or defaults
  change;
- keep the security invariants of the [threat model](docs/threat-model.md): every
  authentication failure is counted, nothing secret is logged or stored in
  clear, a banned IP only gets responses marked `Authenticated`.

`git config core.hooksPath .githooks` enables a pre-push hook that runs
`ci/run.sh` on a clean worktree of each pushed commit.

Contributions are accepted under the MIT license of this repository.
