---
name: Bug report
about: Something is broken or wrong on a node, in consensus, or in the API
title: "[BUG] <area>: <what is wrong, in one line>"
labels: bug
assignees: ""
---

## Action performed
1. …
2. …
3. …

## Expected result
<!-- What should happen. Quote the rule, doc or constant it should follow. -->

## Actual result
<!-- What happens instead. -->

## Where it happens
- [ ] Mainnet (node 1 / node 2 / node 3 / SS / AZ / Rooverse)
- [ ] Test cluster (N1 / N2 / N3)
- [ ] Local (docker compose / jest)

**Node version:** `/v1/health` → `…`
**Round / state root when seen:** `…`
**Consensus impact:** none / one node disagrees / fleet halted / fork (say which nodes)

## Evidence
<!-- Log lines, tx ids, CTIDs, TIP-IDs, DB rows, API responses. Never keys, tokens, passwords, gov IDs or DOBs. -->

## Workaround
<!-- How an operator or user gets past it today, or "None". -->

## Tests required
<!-- What an automated test must prove once this is fixed; name the suite if it exists. -->

## Reported by
<!-- @handle · link to chat or doc -->
