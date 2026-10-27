### Why
<!-- The problem, in plain words, with the real case that showed it. -->

### What changes
<!-- Each change and the file it lives in. No issue numbers in source or tests. -->

### Fixed issues
<!-- The issue stays open until the change is verified on the deployed build; close it by hand then. -->
Fixes #

### Consensus impact
- [ ] None
- [ ] Commit rule change: gated on `…ACTIVATION_MS` = `<date UTC>`; override `TIP_…_ACTIVATION_MS` for an isolated cluster; every node (partners included) on this release before the epoch

### Tests
- [ ] New or changed tests **fail on the old code** and pass on the new
- [ ] Full node suite run (`npm test`, runInBand); result pasted in a comment, failures listed as "also fails on main" or "flaky"
- [ ] Test cluster: rolled 3,2,1 through the root gate, each MATCH, 0 halts, roots equal; what was exercised

### Before merge and deploy
- [ ] Version bump, CHANGELOG, `docs/DEPLOYMENT.md` sample (releases only)
- [ ] Env changes listed, `.env.example` updated, generated partner envs still correct
- [ ] Deploy order: mainnet 3,2,1 through the gate, then SS, then partners; tag, Hub image, GitHub release
- [ ] No secrets, keys, gov IDs or personal data in code, tests, logs or screenshots
