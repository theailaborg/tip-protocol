"""
Walk-through: an agent edits a page on someone else's site, then a third
party checks the record. Prints the three answers and the attack outcomes.

    python demo.py                  # narrated run
    python demo.py --export out/    # also write the evidence bundles as JSON

License: TIPCL-1.0 (see LICENSE.txt at the repository root).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import time

import tip_agentic as ta

T0 = 1_800_000_000_000
HOUR = 3_600_000
DOCS = "https://site.example/docs/"
PAGE = "https://site.example/docs/pricing/plan.txt"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", type=pathlib.Path, help="directory for JSON evidence bundles")
    ap.add_argument("--receipts", type=int, default=200, help="receipts for the timing run")
    args = ap.parse_args()

    now = [T0]
    directory = ta.IdentityDirectory()

    def identity(region: str) -> tuple[ta.Signer, str]:
        s = ta.Signer.generate()
        i = ta.tip_id(region, s.public_key_hex)
        directory.register(i, s.public_key_hex)
        return s, i

    org, org_id = identity("IN")            # the principal: a company with a TIP-ID
    other, other_id = identity("US")        # another company, used for impersonation
    site, site_id = identity("IN")          # the website the agent acts on
    agent = ta.Signer.generate()            # the company's agent
    helper = ta.Signer.generate()           # a sub-agent it hands work to
    rogue = ta.Signer.generate()

    root = ta.issue_delegation(org, org_id, agent.public_key_hex,
                               ta.make_scope(["read", "create", "edit"], [DOCS]), T0 - HOUR, T0 + HOUR)
    child = ta.issue_delegation(agent, ta.agent_id(agent.public_key_hex), helper.public_key_hex,
                                ta.make_scope(["edit"], [DOCS + "pricing/"]), T0 - HOUR, T0 + HOUR,
                                parent=ta.record_id(root))
    chain = [ta.record_id(root), ta.record_id(child)]

    gw = ta.SiteGateway(site, site_id, directory, lambda: now[0])
    gw.store[PAGE] = b"balance=0"

    print("Principal :", org_id)
    print("Site      :", site_id)
    print("Agent     :", ta.agent_id(agent.public_key_hex), "-> sub-agent", ta.agent_id(helper.public_key_hex))
    print()

    req = ta.make_request(helper, chain, "edit", PAGE, now[0], content=b"balance=+100", base=b"balance=0")
    out = gw.submit(req, [root, child], (), b"balance=+100")
    good = ta.evidence_bundle(req, out, [root, child])
    v = ta.verify_evidence(good, directory, content=b"balance=+100")

    a = v.answers
    print(f"Independent check: {v.status.upper()}")
    print("  Which agent acted?      ", a["which_agent"]["agent"])
    print("  On whose authority?     ", a["on_whose_authority"]["principal"],
          "via", " -> ".join(a["on_whose_authority"]["chain_issuers"]))
    w = a["what_it_did"]
    print("  What did it do?         ", w["action"], w["resource"], w["decision"])
    print("     before", w["before_hash"][:16], "after", w["after_hash"][:16], "at", w["decided_at"])
    print()

    def attempt(label: str, request: dict, delegations, content=None, revocations=()):
        o = gw.submit(request, delegations, revocations, content)
        b = o["receipt"]["body"]
        print(f"  {label:<46} {b['decision']:<9} {b['reason']}")
        return o

    print("Attacks and mistakes (each refusal is itself a signed, logged receipt):")
    forged = ta.issue_delegation(other, org_id, rogue.public_key_hex,
                                 ta.make_scope(["edit"], [DOCS]), T0 - HOUR, T0 + HOUR)
    attempt("Other company signs authority in org's name",
            ta.make_request(rogue, [ta.record_id(forged)], "edit", PAGE, now[0], b"x", gw.store[PAGE]),
            [forged], b"x")
    attempt("Stolen chain used with a different key",
            ta.make_request(rogue, chain, "edit", PAGE, now[0], b"x", gw.store[PAGE]), [root, child], b"x")
    attempt("Sub-agent tries delete (not granted)",
            ta.make_request(helper, chain, "delete", PAGE, now[0], None, gw.store[PAGE]), [root, child])
    wider = ta.issue_delegation(agent, ta.agent_id(agent.public_key_hex), helper.public_key_hex,
                                ta.make_scope(["edit", "delete"], [DOCS]), T0 - HOUR, T0 + HOUR,
                                parent=ta.record_id(root))
    attempt("Agent grants sub-agent more than it holds",
            ta.make_request(helper, [chain[0], ta.record_id(wider)], "delete", PAGE, now[0], None, gw.store[PAGE]),
            [root, wider])
    attempt("Signed '+200', delivered '-200'",
            ta.make_request(helper, chain, "edit", PAGE, now[0], b"balance=+200", gw.store[PAGE]),
            [root, child], b"balance=-200")
    attempt("Same request sent twice", req, [root, child], b"balance=+100")
    now[0] += 60_000                          # a minute after the good edit
    rv = ta.issue_revocation(org, org_id, chain[0], now[0])
    now[0] += 1
    attempt("Principal revoked the agent",
            ta.make_request(helper, chain, "edit", PAGE, now[0], b"balance=+300", gw.store[PAGE]),
            [root, child], b"balance=+300", [rv])
    print()

    later = ta.verify_evidence(ta.evidence_bundle(req, out, [root, child], [rv]), directory)
    print("Earlier edit re-checked after the revocation:", later.status.upper(),
          "(authority is judged at the time of the action)")

    tampered = json.loads(json.dumps(good))
    tampered["receipt"]["body"]["after_hash"] = ta.content_hash(b"balance=-100")
    print("Same record with the receipt edited afterwards:",
          ta.verify_evidence(tampered, directory).status.upper())
    print()

    bench = ta.SiteGateway(site, site_id, directory, lambda: now[0])
    rv_free = ta.issue_delegation(org, org_id, agent.public_key_hex,
                                  ta.make_scope(["create"], [DOCS]), T0 - HOUR, T0 + 10 * HOUR)
    reqs = [ta.make_request(agent, [ta.record_id(rv_free)], "create", f"{DOCS}n/{i}", now[0], f"{i}".encode())
            for i in range(args.receipts)]
    t = time.perf_counter()
    for i, r in enumerate(reqs):
        bench.submit(r, [rv_free], (), f"{i}".encode())
    dt = time.perf_counter() - t
    print(f"Timing: {args.receipts} checked and receipted actions in {dt:.2f}s "
          f"({args.receipts / dt:.0f}/s, single thread, this machine, checkpoint re-signed every time)")

    if args.export:
        args.export.mkdir(parents=True, exist_ok=True)
        (args.export / "valid_edit.json").write_text(json.dumps(good, indent=2))
        (args.export / "tampered_receipt.json").write_text(json.dumps(tampered, indent=2))
        (args.export / "directory.json").write_text(json.dumps(
            {i: directory.key_for(i) for i in (org_id, other_id, site_id)}, indent=2))
        print("Evidence written to", args.export)


if __name__ == "__main__":
    main()
