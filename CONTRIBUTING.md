# Contributing to TIP Protocol

Thank you for your interest in contributing to TIP Protocol. This document
explains how to contribute effectively and what to expect from the process.

## Before You Start

**Read the license.** TIP Protocol is licensed under TIPCL-1.0. By submitting
a contribution, you agree that your contribution is licensed under the same
terms. See [LICENSE.txt](./LICENSE.txt).

**Read the Code of Conduct.** All contributors must follow our
[Code of Conduct](./CODE_OF_CONDUCT.md).

**For security vulnerabilities:** Do NOT open a public issue. Follow the
responsible disclosure process in [SECURITY.md](./SECURITY.md).

---

## Types of Contributions

### Good First Contributions

These are great starting points and do not require deep protocol knowledge:

- Documentation improvements (typos, clarity, examples)
- Additional language SDKs (Go, Rust, Java, Swift)
- Test coverage improvements
- Code comments and inline documentation
- Translation of documentation

### Standard Contributions

These require understanding the protocol but follow the normal PR process:

- Bug fixes in non-core modules (SDK, CLI, browser extension, badge component)
- Additional API endpoints
- Performance improvements that do not change protocol behaviour
- New test cases

### Protocol Core Changes

**Changes to the DAG engine, trust scoring, identity registration,
cryptographic verification, or the genesis block format require the
RFC (Request for Comments) process.**

Do not submit a pull request for protocol core changes without a prior
RFC. The RFC process exists because changes to the core protocol affect
every node on the network and every implementation worldwide.

RFC process: [docs/RFC_PROCESS.md](./docs/RFC_PROCESS.md)

---

## Development Setup

### Prerequisites

- Node.js 18+ (for Node.js implementation)
- Python 3.11+ (for Python implementation)
- Git 2.30+

### Setup

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/tip-protocol.git
cd tip-protocol
git remote add upstream https://github.com/theailab/tip-protocol.git

# Node.js setup
npm install
cp .env.example .env
npm test  # Should pass all tests

# Python setup
cd python
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
python -m pytest tests/ -v  # Should pass 201 tests
```

---

## Pull Request Process

### 1. Create a branch

```bash
git checkout -b fix/your-description
# or
git checkout -b feature/your-description
# or
git checkout -b docs/your-description
```

Branch naming:
- `fix/`: bug fixes
- `feature/`: new features
- `docs/`: documentation only
- `test/`: test additions or fixes
- `refactor/`: code refactoring without behaviour change

### 2. Make your changes

- Write or update tests for your changes
- Ensure all existing tests pass (`npm test` or `pytest`)
- Follow the code style of the surrounding code
- Do not break the API surface without a deprecation period

### 3. Commit message format

We follow the Conventional Commits specification:

```
type(scope): short description

Longer explanation if needed. Wrap at 72 characters.

Closes #123
```

Types: `fix`, `feat`, `docs`, `test`, `refactor`, `chore`, `perf`

Examples:
```
fix(trust): correct score calculation for social attestation events
feat(api): add GET /v1/identity/:id/history endpoint
docs(readme): clarify VP accreditation process
test(dag): add edge case for concurrent transaction validation
```

### 4. Open a pull request

- Fill out the pull request template completely
- Link any related issues
- Describe what you changed and why
- Include test results

### 5. Review process

All pull requests require:
- At least one review from a project maintainer
- All CI checks passing (lint, tests, type checks)
- No merge conflicts with `main`

Protocol core changes additionally require:
- An accepted RFC
- Review from two maintainers
- 14-day comment period on the PR

---

## Contributor License Agreement

By submitting a pull request, you certify that:

1. The contribution is your original work or you have the right to submit it.
2. You grant The AI Lab Intelligence Unobscured, Inc. a perpetual, worldwide,
   non-exclusive, royalty-free license to use, reproduce, modify, and
   distribute your contribution as part of TIP Protocol.
3. You understand that your contribution will be licensed under TIPCL-1.0
   and may later be relicensed under Apache 2.0 as described in the License.
4. You have read and agree to the [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## What We Do Not Accept

The following will not be merged and may be closed without discussion:

- Changes that remove or weaken post-quantum cryptographic requirements
- Changes that break backward compatibility without an RFC
- Changes that remove attribution or NOTICE file requirements
- Code that adds dependencies with incompatible licenses
- Protocol core changes without a prior accepted RFC
- Changes that weaken biometric verification standards
- Additions of centralized components to a federated system

---

## Questions?

- Open a GitHub Discussion for general questions
- Join the developer community at theailab.org/community
- Email: chairman@theailab.org for project-level questions

---

*We appreciate every contribution, however small. Documentation fixes,
typo corrections, and test additions are all genuinely valuable.*
