"""
Tests for the agentic provenance reference demo.

Run from this directory:  python -m pytest -q
License: TIPCL-1.0 (see LICENSE.txt at the repository root).
"""

from __future__ import annotations

import copy
import json

import pytest

import tip_agentic as ta

T0 = 1_800_000_000_000
HOUR = 3_600_000
DOCS = "https://site.example/docs/"
PLAN = "https://site.example/docs/pricing/plan.txt"


class World:
    def __init__(self) -> None:
        self.now = T0
        self.directory = ta.IdentityDirectory()

        self.principal = ta.Signer.generate()
        self.principal_id = ta.tip_id("IN", self.principal.public_key_hex)
        self.directory.register(self.principal_id, self.principal.public_key_hex)

        self.impostor = ta.Signer.generate()
        self.impostor_id = ta.tip_id("US", self.impostor.public_key_hex)
        self.directory.register(self.impostor_id, self.impostor.public_key_hex)

        self.site_key = ta.Signer.generate()
        self.site_id = ta.tip_id("IN", self.site_key.public_key_hex)
        self.directory.register(self.site_id, self.site_key.public_key_hex)

        self.agent = ta.Signer.generate()
        self.agent_id = ta.agent_id(self.agent.public_key_hex)
        self.sub = ta.Signer.generate()
        self.rogue = ta.Signer.generate()

        self.root = ta.issue_delegation(
            self.principal, self.principal_id, self.agent.public_key_hex,
            ta.make_scope(["read", "create", "edit"], [DOCS]), T0 - HOUR, T0 + HOUR,
        )
        self.root_id = ta.record_id(self.root)
        self.child = ta.issue_delegation(
            self.agent, self.agent_id, self.sub.public_key_hex,
            ta.make_scope(["edit"], [DOCS + "pricing/"]), T0 - HOUR, T0 + HOUR,
            parent=self.root_id,
        )
        self.child_id = ta.record_id(self.child)

        self.gw = ta.SiteGateway(self.site_key, self.site_id, self.directory, lambda: self.now)
        self.gw.store[PLAN] = b"balance=0"

    def edit(self, signer=None, chain=None, content=b"balance=+100", resource=PLAN, action="edit", **kw):
        signer = signer or self.sub
        chain = chain if chain is not None else [self.root_id, self.child_id]
        base = kw.pop("base", self.gw.store.get(resource))
        content = None if action in ("delete", "read") else content
        return ta.make_request(signer, chain, action, resource, self.now, content=content, base=base, **kw)

    def submit(self, request, delegations=None, revocations=(), content=b"balance=+100"):
        delegations = delegations if delegations is not None else [self.root, self.child]
        if request["body"]["action"] in ("delete", "read"):
            content = None
        return self.gw.submit(request, delegations, revocations, content)

    def bundle(self, request, outcome, delegations=None, revocations=()):
        delegations = delegations if delegations is not None else [self.root, self.child]
        return ta.evidence_bundle(request, outcome, delegations, revocations)


@pytest.fixture
def w() -> World:
    return World()


def decision(outcome):
    b = outcome["receipt"]["body"]
    return b["decision"], b["reason"]


# --- The good path: all three questions answered ---------------------------

def test_delegated_edit_commits_and_answers_the_three_questions(w):
    req = w.edit()
    out = w.submit(req)
    assert decision(out) == ("committed", "")
    assert w.gw.store[PLAN] == b"balance=+100"

    v = ta.verify_evidence(w.bundle(req, out), w.directory, content=b"balance=+100")
    assert v.status == ta.VALID, v.reasons
    assert v.answers["which_agent"]["agent"] == ta.agent_id(w.sub.public_key_hex)
    assert v.answers["on_whose_authority"]["principal"] == w.principal_id
    assert v.answers["on_whose_authority"]["chain_issuers"] == [w.principal_id, w.agent_id]
    did = v.answers["what_it_did"]
    assert (did["action"], did["resource"], did["decision"]) == ("edit", PLAN, "committed")
    assert did["before_hash"] == ta.content_hash(b"balance=0")
    assert did["after_hash"] == ta.content_hash(b"balance=+100")


def test_evidence_survives_json_round_trip(w):
    req = w.edit()
    bundle = json.loads(json.dumps(w.bundle(req, w.submit(req))))
    assert ta.verify_evidence(bundle, w.directory).status == ta.VALID


def test_refusals_are_signed_logged_and_verifiable(w):
    req = w.edit(action="delete")
    out = w.submit(req)
    assert out["receipt"]["body"]["decision"] == "rejected"
    v = ta.verify_evidence(w.bundle(req, out), w.directory)
    assert v.status == ta.VALID
    assert v.answers["what_it_did"]["decision"] == "rejected"
    assert len(w.gw.log) == 1


# --- Identity: which agent? -------------------------------------------------

def test_impostor_cannot_issue_authority_in_another_principals_name(w):
    forged = ta.issue_delegation(
        w.impostor, w.principal_id, w.rogue.public_key_hex,
        ta.make_scope(["edit"], [DOCS]), T0 - HOUR, T0 + HOUR,
    )
    req = w.edit(signer=w.rogue, chain=[ta.record_id(forged)])
    d, reason = decision(w.submit(req, delegations=[forged]))
    assert d == "rejected" and "not signed by the key registered for" in reason


def test_stolen_delegation_chain_is_useless_without_the_agent_key(w):
    req = w.edit(signer=w.rogue)
    d, reason = decision(w.submit(req))
    assert d == "rejected" and "acting key is not the key the chain delegates to" in reason


def test_forged_request_signature_is_rejected(w):
    req = w.edit()
    req["sig"] = w.rogue.sign_body(req["body"])["sig"]
    assert decision(w.submit(req)) == ("rejected", "request signature invalid")


def test_unknown_principal_is_not_provable(w):
    stranger = ta.Signer.generate()
    sid = ta.tip_id("IN", stranger.public_key_hex)
    root = ta.issue_delegation(stranger, sid, w.agent.public_key_hex,
                               ta.make_scope(["edit"], [DOCS]), T0 - HOUR, T0 + HOUR)
    req = w.edit(signer=w.agent, chain=[ta.record_id(root)])
    d, reason = decision(w.submit(req, delegations=[root]))
    assert d == "rejected" and "no TIP identity record" in reason


# --- Authority: on whose behalf, and within what limits? -------------------

def test_action_outside_delegated_scope_is_rejected(w):
    d, reason = decision(w.submit(w.edit(action="delete")))
    assert d == "rejected" and "outside the delegated scope" in reason


def test_resource_scope_cannot_be_stretched_by_string_prefix(w):
    # A grant for exactly ".../docs" must not cover ".../docs-evil".
    exact = ta.issue_delegation(
        w.principal, w.principal_id, w.agent.public_key_hex,
        ta.make_scope(["edit"], ["https://site.example/docs"]), T0 - HOUR, T0 + HOUR,
    )
    evil = "https://site.example/docs-evil"
    w.gw.store[evil] = b"x"
    req = w.edit(signer=w.agent, chain=[ta.record_id(exact)], resource=evil)
    d, reason = decision(w.submit(req, delegations=[exact]))
    assert d == "rejected" and "outside the delegated scope" in reason


def test_sub_agent_cannot_grant_itself_more_than_it_was_given(w):
    wider = ta.issue_delegation(
        w.agent, w.agent_id, w.sub.public_key_hex,
        ta.make_scope(["edit", "delete"], [DOCS]), T0 - HOUR, T0 + HOUR, parent=w.root_id,
    )
    req = w.edit(action="delete", chain=[w.root_id, ta.record_id(wider)])
    d, reason = decision(w.submit(req, delegations=[w.root, wider]))
    assert d == "rejected" and "wider than its parent" in reason


def test_sub_delegation_from_a_key_never_delegated_to_is_rejected(w):
    bogus = ta.issue_delegation(
        w.rogue, ta.agent_id(w.rogue.public_key_hex), w.sub.public_key_hex,
        ta.make_scope(["edit"], [DOCS]), T0 - HOUR, T0 + HOUR, parent=w.root_id,
    )
    req = w.edit(chain=[w.root_id, ta.record_id(bogus)])
    d, reason = decision(w.submit(req, delegations=[w.root, bogus]))
    assert d == "rejected" and "never delegated to" in reason


def test_sub_delegation_cannot_outlive_its_parent(w):
    longer = ta.issue_delegation(
        w.agent, w.agent_id, w.sub.public_key_hex,
        ta.make_scope(["edit"], [DOCS]), T0 - HOUR, T0 + 2 * HOUR, parent=w.root_id,
    )
    req = w.edit(chain=[w.root_id, ta.record_id(longer)])
    d, reason = decision(w.submit(req, delegations=[w.root, longer]))
    assert d == "rejected" and "outlives its parent" in reason


def test_repeated_link_in_chain_is_rejected(w):
    req = w.edit(chain=[w.root_id, w.child_id, w.root_id])
    d, reason = decision(w.submit(req))
    assert d == "rejected" and "cycle" in reason


def test_expired_authority_is_rejected(w):
    w.now = T0 + HOUR
    d, reason = decision(w.submit(w.edit()))
    assert d == "rejected" and "not valid at" in reason


def test_revocation_by_the_principal_stops_the_whole_chain(w):
    rv = ta.issue_revocation(w.principal, w.principal_id, w.root_id, T0 - 1)
    d, reason = decision(w.submit(w.edit(), revocations=[rv]))
    assert d == "rejected" and "revoked" in reason


def test_revocation_from_an_unrelated_party_is_ignored(w):
    rv = ta.issue_revocation(w.impostor, w.impostor_id, w.root_id, T0 - 1)
    assert decision(w.submit(w.edit(), revocations=[rv]))[0] == "committed"


def test_later_revocation_does_not_rewrite_history(w):
    req = w.edit()
    out = w.submit(req)
    rv = ta.issue_revocation(w.principal, w.principal_id, w.root_id, T0 + 1000)
    v = ta.verify_evidence(w.bundle(req, out, revocations=[rv]), w.directory)
    assert v.status == ta.VALID
    w.now = T0 + 2000
    d, reason = decision(w.submit(w.edit(), revocations=[rv]))
    assert d == "rejected" and "revoked" in reason


# --- Activity: what exactly did it do? --------------------------------------

def test_one_character_substitution_is_caught(w):
    # Agent signed "+100"; "-100" is delivered. TIP's CNA-2 text fingerprint
    # treats these as the same text, so the commitment must be exact bytes.
    assert ta.content_hash(b"balance=+100") != ta.content_hash(b"balance=-100")
    req = w.edit(content=b"balance=+100")
    d, reason = decision(w.submit(req, content=b"balance=-100"))
    assert d == "rejected" and "does not match what the agent signed" in reason
    assert w.gw.store[PLAN] == b"balance=0"


def test_replayed_request_is_rejected(w):
    req = w.edit()
    assert decision(w.submit(req))[0] == "committed"
    assert decision(w.submit(req)) == ("rejected", "replayed request")


def test_stale_or_future_request_is_rejected(w):
    req = w.edit()
    w.now = T0 + 10 * 60_000
    assert decision(w.submit(req)) == ("rejected", "request is stale or future-dated")


def test_edit_based_on_an_outdated_read_is_rejected(w):
    req = w.edit(base=b"balance=old")
    d, reason = decision(w.submit(req))
    assert d == "rejected" and "changed since the agent read it" in reason


# --- Independent verification of the record --------------------------------

def test_tampered_receipt_is_detected(w):
    req = w.edit()
    bundle = w.bundle(req, w.submit(req))
    bundle["receipt"]["body"]["after_hash"] = ta.content_hash(b"balance=-100")
    v = ta.verify_evidence(bundle, w.directory)
    assert v.status == ta.INVALID and "receipt not signed" in v.reasons[0]


def test_receipt_cannot_be_paired_with_a_different_request(w):
    req = w.edit()
    out = w.submit(req)
    other = w.edit(content=b"balance=+999")
    v = ta.verify_evidence(w.bundle(other, out), w.directory)
    assert v.status == ta.INVALID and "different request" in v.reasons[0]


def test_receipt_missing_from_log_is_detected(w):
    req = w.edit()
    bundle = w.bundle(req, w.submit(req))
    bundle["proof"] = [{"hash": "00" * 32, "position": "left"}]
    v = ta.verify_evidence(bundle, w.directory)
    assert v.status == ta.INVALID and "not in the checkpointed log" in v.reasons[0]


def test_checkpoint_signed_by_another_key_is_rejected(w):
    req = w.edit()
    bundle = w.bundle(req, w.submit(req))
    bundle["checkpoint"] = w.rogue.sign_body(bundle["checkpoint"]["body"])
    v = ta.verify_evidence(bundle, w.directory)
    assert v.status == ta.INVALID and "checkpoint" in v.reasons[0]


def test_verifier_does_not_take_the_sites_word_for_authority(w):
    # A careless or compromised receiver commits an out-of-scope delete.
    req = w.edit(action="delete")
    body = req["body"]
    before = ta.content_hash(w.gw.store.pop(PLAN))
    out = w.gw._record(req, body, "committed", "", before, None, w.now)
    v = ta.verify_evidence(w.bundle(req, out), w.directory)
    assert v.status == ta.INVALID and "does not authorise" in v.reasons[0]


def test_missing_delegation_makes_the_record_indeterminate_not_valid(w):
    req = w.edit()
    out = w.submit(req)
    v = ta.verify_evidence(w.bundle(req, out, delegations=[w.root]), w.directory)
    assert v.status == ta.INDETERMINATE


def test_content_shown_to_verifier_must_match_the_commit(w):
    req = w.edit()
    bundle = w.bundle(req, w.submit(req))
    v = ta.verify_evidence(bundle, w.directory, content=b"balance=-100")
    assert v.status == ta.INVALID


def test_every_receipt_in_a_longer_log_stays_provable(w):
    outcomes = []
    for i in range(7):
        req = w.edit(content=f"balance={i}".encode())
        outcomes.append((req, w.gw.submit(req, [w.root, w.child], (), f"balance={i}".encode())))
    root = ta.merkle_root(w.gw.log)
    for i, (_, out) in enumerate(outcomes):
        rid = ta.record_id(out["receipt"])
        assert ta.verify_merkle_proof(rid, ta.merkle_proof(w.gw.log, i), root)


# --- Conformance with TIP conventions ---------------------------------------

def test_canonical_json_follows_tip_rules():
    assert ta.canonical_json({"b": 1, "a": [True, None, "x"], "c": {"z": "é", "y": "\n"}}) == \
        '{"a":[true,null,"x"],"b":1,"c":{"y":"\\n","z":"é"}}'
    # JS sorts keys by UTF-16 code unit, which differs from code-point order
    # for characters outside the BMP.
    assert ta.canonical_json({"\U0001F600": 1, "～": 2}) == '{"\U0001F600":1,"～":2}'
    with pytest.raises(TypeError):
        ta.canonical_json({"x": 1.5})


def test_merkle_matches_tip_construction():
    L = lambda x: ta.shake256("L" + x)
    N = lambda a, b: ta.shake256("N" + a + b)
    assert ta.merkle_root(["a", "b", "c"]) == N(N(L("a"), L("b")), L("c"))
    assert ta.merkle_root(["a", "b", "c"]) != ta.merkle_root(["a", "b", "c", "c"])
    assert ta.merkle_root([]) == ta.shake256("tip-merkle-empty-tree")
    for n in range(1, 10):
        items = [str(i) for i in range(n)]
        root = ta.merkle_root(items)
        for i in range(n):
            assert ta.verify_merkle_proof(items[i], ta.merkle_proof(items, i), root)


def test_every_record_names_its_algorithms(w):
    req = w.edit()
    out = w.submit(req)
    for rec in (w.root, w.child, req, out["receipt"], out["checkpoint"]):
        assert rec["body"]["sig_alg"] == "ML-DSA-65"
        assert rec["body"]["hash_alg"] == "SHAKE-256"


def test_unlisted_or_missing_algorithm_label_is_refused():
    s = ta.Signer.generate()
    for label in ({"sig_alg": "Ed25519", "hash_alg": "SHAKE-256"},
                  {"sig_alg": "ML-DSA-65", "hash_alg": "SHA-1"},
                  {}):
        body = {"x": 1, **label}
        # The signature math is valid ML-DSA-65; only the label is wrong.
        sig = s._sk.sign(ta.shake256(ta.canonical_json(body)).encode("ascii")).hex()
        assert not ta.verify_body(body, sig, s.public_key_hex)


def test_relabelled_request_is_rejected_by_the_site(w):
    req = w.edit()
    req["body"]["sig_alg"] = "Ed25519"
    assert decision(w.submit(req)) == ("rejected", "request signature invalid")


def test_tip_id_and_key_sizes():
    s = ta.Signer.generate()
    assert len(bytes.fromhex(s.public_key_hex)) == 1952
    rec = s.sign_body({"x": 1})
    assert len(bytes.fromhex(rec["sig"])) == 3309
    assert ta.tip_id("in", s.public_key_hex) == f"tip://id/IN-{ta.shake256(s.public_key_hex)[:16]}"
