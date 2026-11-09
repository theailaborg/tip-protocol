"""
Agentic provenance on TIP primitives: a reference demo.

Answers three questions about an AI agent's action on someone else's
system, using evidence anyone can check with public keys alone:

  1. Which agent acted?           (agent identity provenance)
  2. On whose authority?          (signed delegation chain to a TIP-ID)
  3. What exactly did it do?      (signed request + receiver's receipt,
                                   kept in an append-only Merkle log)

It reuses TIP's existing conventions rather than inventing new ones:

  - ML-DSA-65 (FIPS 204) signatures and SHAKE-256 hashing
  - canonical JSON with recursively sorted keys (shared/crypto.js canonicalJson)
  - the signBody convention: sign(shake256(canonicalJson(fields)))
  - TIP-ID derivation: tip://id/<REGION>-<shake256(pubkey_hex)[:16]>
  - the Merkle construction in shared/merkle.js (L/N prefixes, odd node promoted)

Nothing here changes TIP's DAG, transaction format or consensus. Records live
off-ledger; the receiver's signed log checkpoint is the natural thing to
anchor in TIP. A protocol-level version would go through the RFC process.

License: TIPCL-1.0 (see LICENSE.txt at the repository root).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA65PrivateKey,
        MLDSA65PublicKey,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "This demo needs a 'cryptography' release with ML-DSA support "
        "(cryptography.hazmat.primitives.asymmetric.mldsa); tested with 50.0.1."
    ) from exc


SCHEMA = "tip-agentic-provenance/v1"
ACTIONS = ("read", "create", "edit", "delete")
WRITE_ACTIONS = ("create", "edit")
MAX_CHAIN_DEPTH = 4
MLDSA65_PUBKEY_BYTES = 1952

VALID = "valid"
INVALID = "invalid"
INDETERMINATE = "indeterminate"


# --- Hashing and canonical form (mirrors shared/crypto.js) -----------------

def shake256(data: bytes | str, output_bytes: int = 32) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.shake_256(data).hexdigest(output_bytes)


def _utf16_key(k: str) -> bytes:
    # JS Array.prototype.sort() orders strings by UTF-16 code units.
    return k.encode("utf-16-be", "surrogatepass")


def canonical_json(obj: Any) -> str:
    """Byte-for-byte mirror of canonicalJson() in shared/crypto.js.

    Records in this demo hold only strings, integers, booleans, null, lists
    and objects. Floats are refused because JS and Python print some of them
    differently, which would silently break cross-language verification.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        if abs(obj) > 2**53 - 1:
            raise ValueError("integer outside the JS safe range")
        return str(obj)
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in signed records")
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in obj) + "]"
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
        keys = sorted(obj, key=_utf16_key)
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical_json(obj[k]) for k in keys
        ) + "}"
    raise TypeError(f"unsupported type in signed record: {type(obj).__name__}")


def content_hash(content: bytes) -> str:
    """Exact-bytes commitment (full 256-bit SHAKE-256).

    Deliberately NOT TIP's CNA-2 hashContent(): CNA-2 normalises text so a
    published post still matches its registered draft (it lower-cases and
    drops punctuation, so 'balance=+100' and 'balance=-100' share a CNA-2
    hash). That is right for content matching and wrong for authorising an
    action, where one changed character must change the commitment.
    """
    return shake256(content)


def tip_id(region: str, public_key_hex: str) -> str:
    """Same derivation as generateTIPID() in shared/crypto.js."""
    return f"tip://id/{region.upper()}-{shake256(public_key_hex)[:16]}"


def agent_id(public_key_hex: str) -> str:
    # Illustrative identifier only. A real agent namespace in TIP URIs would
    # be an RFC decision; this demo does not mint one.
    return f"tip-agent:{shake256(public_key_hex)[:16]}"


def key_fingerprint(public_key_hex: str) -> str:
    return shake256(public_key_hex)[:16]


# --- Keys and signed records ------------------------------------------------

class Signer:
    """An ML-DSA-65 key that signs records with TIP's signBody convention."""

    def __init__(self, private_key: MLDSA65PrivateKey):
        self._sk = private_key
        self.public_key_hex = private_key.public_key().public_bytes_raw().hex()

    @classmethod
    def generate(cls) -> "Signer":
        return cls(MLDSA65PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Signer":
        return cls(MLDSA65PrivateKey.from_seed_bytes(seed))

    def sign_body(self, body: dict) -> dict:
        digest = shake256(canonical_json(body))
        return {"body": body, "sig": self._sk.sign(digest.encode("ascii")).hex()}


def verify_body(body: dict, sig_hex: str, public_key_hex: str) -> bool:
    try:
        raw = bytes.fromhex(public_key_hex)
        if len(raw) != MLDSA65_PUBKEY_BYTES:
            return False
        pk = MLDSA65PublicKey.from_public_bytes(raw)
        digest = shake256(canonical_json(body))
        pk.verify(bytes.fromhex(sig_hex), digest.encode("ascii"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def record_id(record: dict) -> str:
    """Content address of a signed record: hash of its canonical body."""
    return shake256(canonical_json(record["body"]))


def _verify_record(record: Any, key_field: str) -> bool:
    if not isinstance(record, dict) or not isinstance(record.get("body"), dict):
        return False
    body = record["body"]
    key = body.get(key_field)
    if not isinstance(key, str) or not isinstance(record.get("sig"), str):
        return False
    return verify_body(body, record["sig"], key)


# --- Identity directory (stand-in for TIP identity records) ----------------

class IdentityDirectory:
    """Maps TIP-IDs to their registered public keys.

    In production this lookup is the TIP identity record on the DAG. The
    demo keeps it in memory so the evidence flow can be shown offline.
    """

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}

    def register(self, tip_identity: str, public_key_hex: str) -> None:
        self._keys[tip_identity] = public_key_hex

    def key_for(self, tip_identity: str) -> str | None:
        return self._keys.get(tip_identity)


# --- Scopes -----------------------------------------------------------------

def _resource_matches(resource: str, prefix: str) -> bool:
    # Exact match, or a prefix ending in "/" so ".../docs/" never matches ".../docs-evil".
    return resource == prefix or (prefix.endswith("/") and resource.startswith(prefix))


def _scope_allows(scope: dict, action: str, resource: str) -> bool:
    return action in scope.get("actions", []) and any(
        _resource_matches(resource, p) for p in scope.get("resources", [])
    )


def _scope_within(child: dict, parent: dict) -> bool:
    if not set(child.get("actions", [])) <= set(parent.get("actions", [])):
        return False
    return all(
        any(_resource_matches(r, p) for p in parent.get("resources", []))
        for r in child.get("resources", [])
    )


def make_scope(actions: Iterable[str], resources: Iterable[str]) -> dict:
    actions = sorted(set(actions))
    for a in actions:
        if a not in ACTIONS:
            raise ValueError(f"unknown action {a!r}")
    return {"actions": actions, "resources": sorted(set(resources))}


# --- Record builders -------------------------------------------------------

def issue_delegation(
    issuer: Signer,
    issuer_identity: str,
    subject_key_hex: str,
    scope: dict,
    not_before: int,
    expires_at: int,
    parent: str | None = None,
    issued_at: int | None = None,
) -> dict:
    """A principal (or an agent, for a sub-delegation) authorises an agent key."""
    return issuer.sign_body({
        "schema": SCHEMA,
        "type": "delegation",
        "issuer": issuer_identity,
        "issuer_key": issuer.public_key_hex,
        "subject": agent_id(subject_key_hex),
        "subject_key": subject_key_hex,
        "scope": scope,
        "not_before": not_before,
        "expires_at": expires_at,
        "parent": parent,
        "issued_at": not_before if issued_at is None else issued_at,
        "nonce": secrets.token_hex(16),
    })


def issue_revocation(issuer: Signer, issuer_identity: str, target: str, revoked_at: int) -> dict:
    return issuer.sign_body({
        "schema": SCHEMA,
        "type": "revocation",
        "issuer": issuer_identity,
        "issuer_key": issuer.public_key_hex,
        "target": target,
        "revoked_at": revoked_at,
    })


def make_request(
    agent: Signer,
    chain: list[str],
    action: str,
    resource: str,
    issued_at: int,
    content: bytes | None = None,
    base: bytes | None = None,
    nonce: str | None = None,
) -> dict:
    """The agent signs exactly what it intends to do, before doing it."""
    return agent.sign_body({
        "schema": SCHEMA,
        "type": "action",
        "agent": agent_id(agent.public_key_hex),
        "agent_key": agent.public_key_hex,
        "chain": list(chain),
        "action": action,
        "resource": resource,
        "content_hash": None if content is None else content_hash(content),
        "base_hash": None if base is None else content_hash(base),
        "nonce": nonce or secrets.token_hex(16),
        "issued_at": issued_at,
    })


# --- Authority check (used by the receiver and by independent verifiers) ---

def _well_formed_delegation(d: dict) -> bool:
    scope = d.get("scope")
    return (
        all(isinstance(d.get(k), str) for k in ("issuer", "issuer_key", "subject", "subject_key"))
        and all(isinstance(d.get(k), int) and not isinstance(d.get(k), bool) for k in ("not_before", "expires_at"))
        and isinstance(scope, dict)
        and isinstance(scope.get("actions"), list)
        and isinstance(scope.get("resources"), list)
        and all(isinstance(x, str) for x in scope["actions"] + scope["resources"])
    )


@dataclass
class Authority:
    status: str
    reason: str = ""
    principal: str | None = None
    issuers: list[str] = field(default_factory=list)
    scope: dict | None = None


def check_authority(
    request_body: dict,
    delegations: dict[str, dict],
    revocations: Iterable[dict],
    directory: IdentityDirectory,
    at_ms: int,
) -> Authority:
    chain = request_body.get("chain") or []
    if not isinstance(chain, list) or not chain or not all(isinstance(c, str) for c in chain):
        return Authority(INVALID, "no delegation chain presented")
    if len(chain) > MAX_CHAIN_DEPTH:
        return Authority(INVALID, f"delegation chain longer than {MAX_CHAIN_DEPTH}")
    if len(set(chain)) != len(chain):
        return Authority(INVALID, "delegation chain repeats a link (cycle)")

    bodies: list[dict] = []
    for i, did in enumerate(chain):
        rec = delegations.get(did)
        if rec is None:
            return Authority(INDETERMINATE, f"delegation {did[:12]} not provided")
        if record_id(rec) != did:
            return Authority(INVALID, f"delegation {did[:12]} does not match its id")
        if not _verify_record(rec, "issuer_key"):
            return Authority(INVALID, f"delegation {did[:12]} signature invalid")
        d = rec["body"]
        if d.get("schema") != SCHEMA or d.get("type") != "delegation" or not _well_formed_delegation(d):
            return Authority(INVALID, f"record {did[:12]} is not a well-formed delegation")
        if d["subject"] != agent_id(d["subject_key"]):
            return Authority(INVALID, f"delegation {did[:12]} subject id does not match its key")
        if i == 0:
            if d.get("parent") is not None:
                return Authority(INVALID, "root delegation claims a parent")
            if not str(d["issuer"]).startswith("tip://id/"):
                return Authority(INVALID, "root issuer is not a TIP identity")
            registered = directory.key_for(d["issuer"])
            if registered is None:
                return Authority(INDETERMINATE, f"no TIP identity record for {d['issuer']}")
            if registered != d["issuer_key"]:
                return Authority(
                    INVALID,
                    f"root delegation not signed by the key registered for {d['issuer']}",
                )
        else:
            p = bodies[-1]
            if d.get("parent") != chain[i - 1]:
                return Authority(INVALID, f"delegation {did[:12]} does not point at its parent")
            if d["issuer"] != p["subject"] or d["issuer_key"] != p["subject_key"]:
                return Authority(INVALID, f"delegation {did[:12]} issued by a key that was never delegated to")
            if not _scope_within(d["scope"], p["scope"]):
                return Authority(INVALID, f"sub-delegation {did[:12]} is wider than its parent")
            if d["not_before"] < p["not_before"] or d["expires_at"] > p["expires_at"]:
                return Authority(INVALID, f"sub-delegation {did[:12]} outlives its parent")
        if not (d["not_before"] <= at_ms < d["expires_at"]):
            return Authority(INVALID, f"delegation {did[:12]} not valid at {at_ms}")
        bodies.append(d)

    leaf = bodies[-1]
    if leaf["subject"] != request_body.get("agent") or leaf["subject_key"] != request_body.get("agent_key"):
        return Authority(INVALID, "acting key is not the key the chain delegates to")
    if not _scope_allows(leaf["scope"], request_body.get("action"), request_body.get("resource")):
        return Authority(
            INVALID,
            f"'{request_body.get('action')}' on {request_body.get('resource')} is outside the delegated scope",
        )

    # A revocation counts only if correctly signed by the issuer of the revoked
    # link or of any link above it; unsigned or third-party revocations are ignored.
    position = {did: i for i, did in enumerate(chain)}
    for rv in revocations:
        if not _verify_record(rv, "issuer_key"):
            continue
        r = rv["body"]
        if r.get("type") != "revocation" or r.get("target") not in position:
            continue
        if not isinstance(r.get("revoked_at"), int) or isinstance(r.get("revoked_at"), bool):
            continue
        upto = position[r["target"]]
        allowed = {(bodies[j]["issuer"], bodies[j]["issuer_key"]) for j in range(upto + 1)}
        if (r.get("issuer"), r.get("issuer_key")) not in allowed:
            continue
        if r["revoked_at"] <= at_ms:
            return Authority(INVALID, f"delegation {r['target'][:12]} revoked at {r['revoked_at']}")

    return Authority(
        VALID,
        principal=bodies[0]["issuer"],
        issuers=[b["issuer"] for b in bodies],
        scope=leaf["scope"],
    )


# --- Append-only log (same construction as shared/merkle.js) ---------------

def _leaf_hash(data: str) -> str:
    return shake256("L" + data)


def _node_hash(left: str, right: str) -> str:
    return shake256("N" + left + right)


def _levels(leaves: list[str]) -> list[list[str]]:
    if not leaves:
        return []
    levels = [list(leaves)]
    level = levels[0]
    while len(level) > 1:
        nxt = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # odd node promoted, never duplicated
        levels.append(nxt)
        level = nxt
    return levels


def merkle_root(items: list[str]) -> str:
    if not items:
        return shake256("tip-merkle-empty-tree")
    return _levels([_leaf_hash(x) for x in items])[-1][0]


def merkle_proof(items: list[str], index: int) -> list[dict] | None:
    levels = _levels([_leaf_hash(x) for x in items])
    if not levels or not (0 <= index < len(levels[0])):
        return None
    proof, idx = [], index
    for level in levels[:-1]:
        if len(level) % 2 == 1 and idx == len(level) - 1:
            idx = len(level) // 2
            continue
        sib = idx + 1 if idx % 2 == 0 else idx - 1
        proof.append({"hash": level[sib], "position": "right" if idx % 2 == 0 else "left"})
        idx //= 2
    return proof


def verify_merkle_proof(item: str, proof: Any, root: str) -> bool:
    if not isinstance(proof, list):
        return False
    h = _leaf_hash(item)
    for step in proof:
        if not isinstance(step, dict) or not isinstance(step.get("hash"), str):
            return False
        h = _node_hash(step["hash"], h) if step.get("position") == "left" else _node_hash(h, step["hash"])
    return h == root


# --- The receiving side: a website or API that agents act on ---------------

class SiteGateway:
    """Checks every agent request before it touches the resource, and signs
    a receipt for every decision (commit or refusal) into an append-only log."""

    def __init__(
        self,
        signer: Signer,
        site_identity: str,
        directory: IdentityDirectory,
        clock: Callable[[], int],
        max_skew_ms: int = 300_000,
    ) -> None:
        self.signer = signer
        self.site_identity = site_identity
        self.directory = directory
        self.clock = clock
        self.max_skew_ms = max_skew_ms
        self.store: dict[str, bytes] = {}
        self.log: list[str] = []
        self._seen: set[tuple[str, str]] = set()

    def submit(
        self,
        request: dict,
        delegations: Iterable[dict],
        revocations: Iterable[dict] = (),
        content: bytes | None = None,
    ) -> dict:
        now = self.clock()
        body = request.get("body", {}) if isinstance(request, dict) else {}
        resource = body.get("resource")
        before = self.store.get(resource) if isinstance(resource, str) else None
        before_hash = None if before is None else content_hash(before)
        after_hash = before_hash

        def decide(decision: str, reason: str) -> dict:
            return self._record(request, body, decision, reason, before_hash, after_hash, now)

        if not _verify_record(request, "agent_key") or body.get("type") != "action":
            return decide("rejected", "request signature invalid")
        if body.get("agent") != agent_id(body.get("agent_key", "")):
            return decide("rejected", "agent id does not match the signing key")
        issued_at = body.get("issued_at")
        if not isinstance(issued_at, int) or isinstance(issued_at, bool) or not all(
            isinstance(body.get(k), str) for k in ("action", "resource", "nonce")
        ):
            return decide("rejected", "malformed request")
        if abs(now - issued_at) > self.max_skew_ms:
            return decide("rejected", "request is stale or future-dated")
        replay_key = (body["agent"], str(body.get("nonce")))
        if replay_key in self._seen:
            return decide("rejected", "replayed request")
        self._seen.add(replay_key)

        auth = check_authority(
            body, {record_id(d): d for d in delegations}, list(revocations), self.directory, now
        )
        if auth.status != VALID:
            return decide("rejected", auth.reason)

        action, resource = body["action"], body["resource"]
        if action in WRITE_ACTIONS:
            if content is None or content_hash(content) != body.get("content_hash"):
                return decide("rejected", "delivered content does not match what the agent signed")
        elif body.get("content_hash") is not None or content is not None:
            return decide("rejected", f"'{action}' must not carry content")

        if action == "create":
            if before is not None:
                return decide("rejected", "resource already exists")
        elif before is None:
            return decide("rejected", "resource does not exist")
        elif action in ("edit", "delete") and body.get("base_hash") != before_hash:
            return decide("rejected", "resource changed since the agent read it")

        if action in WRITE_ACTIONS:
            self.store[resource] = content
            after_hash = content_hash(content)
        elif action == "delete":
            del self.store[resource]
            after_hash = None
        return decide("committed", "")

    def _record(self, request, body, decision, reason, before_hash, after_hash, now) -> dict:
        receipt = self.signer.sign_body({
            "schema": SCHEMA,
            "type": "receipt",
            "site": self.site_identity,
            "site_key": self.signer.public_key_hex,
            "request": record_id(request) if isinstance(request, dict) and "body" in request else None,
            "agent": body.get("agent"),
            "chain": body.get("chain"),
            "action": body.get("action"),
            "resource": body.get("resource"),
            "decision": decision,
            "reason": reason,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "decided_at": now,
            "log_index": len(self.log),
        })
        self.log.append(record_id(receipt))
        checkpoint = self.signer.sign_body({
            "schema": SCHEMA,
            "type": "checkpoint",
            "site": self.site_identity,
            "site_key": self.signer.public_key_hex,
            "size": len(self.log),
            "root": merkle_root(self.log),
            "at": now,
        })
        return {
            "receipt": receipt,
            "proof": merkle_proof(self.log, len(self.log) - 1),
            "checkpoint": checkpoint,
        }


# --- Independent verification ----------------------------------------------

@dataclass
class Verdict:
    status: str
    reasons: list[str] = field(default_factory=list)
    answers: dict = field(default_factory=dict)


def evidence_bundle(request: dict, outcome: dict, delegations: Iterable[dict], revocations: Iterable[dict] = ()) -> dict:
    """Everything a third party needs, apart from the public identity directory."""
    return {
        "schema": SCHEMA,
        "request": request,
        "receipt": outcome["receipt"],
        "proof": outcome["proof"],
        "checkpoint": outcome["checkpoint"],
        "delegations": list(delegations),
        "revocations": list(revocations),
    }


def verify_evidence(bundle: dict, directory: IdentityDirectory, content: bytes | None = None) -> Verdict:
    """Check a bundle using only public keys. Never trusts the receiver's word:
    authority is re-derived from the signed chain."""
    receipt, request, checkpoint = bundle.get("receipt"), bundle.get("request"), bundle.get("checkpoint")

    if not isinstance(receipt, dict) or "body" not in receipt:
        return Verdict(INDETERMINATE, ["no receipt"])
    rb = receipt["body"]
    site_key = directory.key_for(rb.get("site", ""))
    if site_key is None:
        return Verdict(INDETERMINATE, [f"no TIP identity record for site {rb.get('site')}"])
    if rb.get("site_key") != site_key or not _verify_record(receipt, "site_key"):
        return Verdict(INVALID, ["receipt not signed by the site's registered key"])

    if not isinstance(checkpoint, dict) or "body" not in checkpoint:
        return Verdict(INDETERMINATE, ["no log checkpoint"])
    cb = checkpoint["body"]
    if cb.get("site") != rb["site"] or cb.get("site_key") != site_key or not _verify_record(checkpoint, "site_key"):
        return Verdict(INVALID, ["log checkpoint not signed by the site"])
    if not (0 <= rb["log_index"] < cb["size"]):
        return Verdict(INVALID, ["receipt index outside the checkpointed log"])
    if not verify_merkle_proof(record_id(receipt), bundle.get("proof"), cb["root"]):
        return Verdict(INVALID, ["receipt is not in the checkpointed log"])

    if not isinstance(request, dict) or "body" not in request:
        return Verdict(INDETERMINATE, ["agent's signed request not provided"])
    if record_id(request) != rb.get("request"):
        return Verdict(INVALID, ["receipt refers to a different request"])
    qb = request["body"]
    if not _verify_record(request, "agent_key") or qb.get("agent") != agent_id(qb.get("agent_key", "")):
        return Verdict(INVALID, ["agent's request signature invalid"])
    for f in ("agent", "chain", "action", "resource"):
        if rb.get(f) != qb.get(f):
            return Verdict(INVALID, [f"receipt '{f}' differs from the signed request"])

    auth = check_authority(
        qb,
        {record_id(d): d for d in bundle.get("delegations", [])},
        bundle.get("revocations", []),
        directory,
        rb["decided_at"],
    )

    answers = {
        "which_agent": {"agent": qb["agent"], "key_fingerprint": key_fingerprint(qb["agent_key"])},
        "on_whose_authority": {
            "principal": auth.principal,
            "chain_issuers": auth.issuers,
            "scope": auth.scope,
            "status": auth.status,
            "reason": auth.reason,
        },
        "what_it_did": {
            "action": qb["action"],
            "resource": qb["resource"],
            "decision": rb["decision"],
            "reason": rb["reason"],
            "before_hash": rb["before_hash"],
            "after_hash": rb["after_hash"],
            "decided_at": rb["decided_at"],
            "site": rb["site"],
        },
    }

    if rb["decision"] == "committed":
        if auth.status == INDETERMINATE:
            return Verdict(INDETERMINATE, [auth.reason], answers)
        if auth.status != VALID:
            return Verdict(INVALID, [f"site committed an action the evidence does not authorise: {auth.reason}"], answers)
        if qb["action"] in WRITE_ACTIONS and rb["after_hash"] != qb["content_hash"]:
            return Verdict(INVALID, ["committed content differs from what the agent signed"], answers)
        if content is not None and content_hash(content) != rb["after_hash"]:
            return Verdict(INVALID, ["content shown differs from the committed content"], answers)
    return Verdict(VALID, [], answers)
