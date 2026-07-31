## Project structure and CI maintenance

- Moved the internal controller entrypoint to `tui/entrypoint.sh`.
- Kept `run.sh` as the only supported user-facing launcher.
- Added `.dockerignore` to keep unrelated repository files out of the Docker build context.
- Moved the Trivy configuration to `.github/ci/trivy.yaml`.
- Updated CI paths and checks to match the new structure.
