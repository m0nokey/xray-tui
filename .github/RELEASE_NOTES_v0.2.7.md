## Documentation and security model

- Added `SECURITY.md` with the security model and reporting guidance.
- Added a threat model covering the local Vault, controller, VPS, and upstream
  dependencies.
- Documented the intentional floating runtime dependency policy and its
  accepted supply-chain risks.
- Changed the recommended installation path to verified GitHub Release archives
  with SHA-256 checksums.
- Kept `main` documented as the branch for development and testing.
