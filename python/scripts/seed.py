#!/usr/bin/env python3
"""
scripts/seed.py
TIP Protocol Python — Production Seed Script

Steps:
  1. Generate (or load) SLH-DSA root keypair
  2. Mint and sign the Genesis Block
  3. Register The AI Lab as founding VP
  4. Create Genesis Ring (founding identities)
  5. Register sample content (all four origin types)
  6. Verify DAG state
  7. Write output files

Usage:
  python scripts/seed.py                     # full seed, direct mode
  python scripts/seed.py --genesis-keys-only # step 1 only
  python scripts/seed.py --node-url http://localhost:4000  # via REST API

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import sys
import urllib.error
import urllib.request

# Allow imports from project root
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from shared.crypto import (
    generate_mldsa_keypair, generate_slhdsa_keypair,
    generate_tip_id, generate_ctid,
    hash_content, mldsa_sign,
    generate_pepper, compute_dedup_hash,
    shake256_multi, compute_zk_proof,
)
from shared.constants import Origin, Protocol, get_tier
from node.genesis import (
    GENESIS_HASH, GENESIS_CHAIN_ID, GENESIS_TIMESTAMP,
    get_founding_vp, build_genesis_block, validate_genesis_block,
    _compute_genesis_hash, GENESIS_PAYLOAD, canonical_json,
)
from node.config import load_config

# ─── Terminal colours ─────────────────────────────────────────────────────────
R = "\x1b[0m"; BOLD = "\x1b[1m"; DIM = "\x1b[2m"
GRN = "\x1b[32m"; YLW = "\x1b[33m"; RED = "\x1b[31m"; CYN = "\x1b[36m"
BGNAVY = "\x1b[44m"; WHT = "\x1b[37m"

def ok(m):    print(f"  {GRN}✓{R} {m}")
def warn(m):  print(f"  {YLW}⚠{R} {m}")
def info(m):  print(f"  {CYN}ℹ{R} {m}")
def fail(m):  print(f"  {RED}✗{R} {m}")
def lbl(k, v): print(f"    {DIM}{k:<28}{R}{v}")
def sep(t):   print(f"\n  {BOLD}{YLW}{'─'*3} {t} {R}")


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _post(url: str, body: dict) -> dict:
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


# ─── Step 1: Genesis keys ─────────────────────────────────────────────────────

def step1_genesis_keys(data_dir: pathlib.Path) -> dict:
    sep("STEP 1: Genesis Root Keypair (SLH-DSA-128s)")
    keys_file = data_dir / "genesis-keys.json"

    if keys_file.exists():
        warn("genesis-keys.json already exists — loading existing keys")
        keys = json.loads(keys_file.read_text())
        lbl("Public key (first 32)", keys["publicKey"][:32] + "...")
        return keys

    info("Generating SLH-DSA-128s root keypair...")
    keys = generate_slhdsa_keypair()
    lbl("Algorithm",              keys["algorithm"])
    lbl("Public key (first 32)", keys["publicKey"][:32] + "...")

    data_dir.mkdir(parents=True, exist_ok=True)
    keys_file.write_text(json.dumps({
        "algorithm":  keys["algorithm"],
        "publicKey":  keys["publicKey"],
        "privateKey": keys["privateKey"],
        "created_at": _utc_now(),
        "purpose":    "TIP Protocol Genesis Block root signing key",
    }, indent=2))
    # Restrict permissions (Unix only)
    try:
        os.chmod(keys_file, 0o600)
    except AttributeError:
        pass

    ok("Genesis root keypair generated and saved")
    warn("SECURITY: genesis-keys.json is chmod 600. Back it up offline. NEVER commit to git.")
    return keys


# ─── Step 2: Mint genesis block ───────────────────────────────────────────────

def step2_genesis_block(data_dir: pathlib.Path, root_keys: dict) -> dict:
    sep("STEP 2: Minting Genesis Block")
    genesis_file = data_dir / "genesis.json"

    if genesis_file.exists():
        info("genesis.json already exists — validating...")
        block = json.loads(genesis_file.read_text())
        if validate_genesis_block(block):
            ok(f"Genesis block valid. Hash: {CYN}{block['genesis_hash'][:32]}...{R}")
            return block
        raise ValueError(
            f"FATAL: genesis.json hash mismatch!\n"
            f"Expected: {GENESIS_HASH}\nGot: {block.get('genesis_hash')}"
        )

    info("Computing genesis hash...")
    genesis_hash = _compute_genesis_hash()
    lbl("Genesis hash",     genesis_hash[:32] + "...")
    lbl("Chain ID",         GENESIS_CHAIN_ID)
    lbl("Protocol version", Protocol.VERSION)
    lbl("Timestamp",        GENESIS_TIMESTAMP)
    lbl("Issuer",           Protocol.ISSUER)

    info("Signing with SLH-DSA-128s root key...")
    signature = mldsa_sign(genesis_hash, root_keys["privateKey"])
    ok("Signature computed")

    block = dict(GENESIS_PAYLOAD)
    block.update({
        "genesis_hash":      genesis_hash,
        "canonical_hash":    shake256_multi(canonical_json(GENESIS_PAYLOAD)),
        "signed_at":         _utc_now(),
        "signer_public_key": root_keys["publicKey"],
        "signature":         signature,
        "environment":       os.environ.get("TIP_ENV", "production"),
    })

    genesis_file.write_text(json.dumps(block, indent=2, sort_keys=True))
    ok(f"Genesis block written to: {genesis_file}")
    ok(f"{BOLD}Genesis hash: {CYN}{genesis_hash}{R}")
    return block


# ─── Step 3: Register founding VP ────────────────────────────────────────────

def step3_founding_vp(
    genesis_block: dict, node_url: str | None, direct: bool
) -> tuple[dict, dict]:
    sep("STEP 3: Register The AI Lab Verification Provider")
    founding_vp = get_founding_vp()
    vp_keypair  = generate_mldsa_keypair()

    info(f"Registering VP: {founding_vp['name']}")
    lbl("Jurisdiction tier", founding_vp["jurisdiction_tier"])
    lbl("URL",               founding_vp["url"])

    if direct or not node_url:
        vp_record = {
            "vp_id":             founding_vp["vp_id"],
            "name":              founding_vp["name"],
            "jurisdiction_tier": founding_vp["jurisdiction_tier"],
            "public_key":        vp_keypair["publicKey"],
            "status":            "active",
            "registered_at":     _utc_now(),
        }
        ok("Founding VP record built (direct mode)")
    else:
        try:
            vp_record = _post(f"{node_url}/v1/vp/register", {
                "name":              founding_vp["name"],
                "jurisdiction_tier": founding_vp["jurisdiction_tier"],
                "public_key":        vp_keypair["publicKey"],
            })
            ok("Founding VP registered via API")
        except Exception as exc:
            warn(f"API registration failed: {exc} — falling back to direct mode")
            vp_record = {
                "vp_id":             founding_vp["vp_id"],
                "name":              founding_vp["name"],
                "jurisdiction_tier": founding_vp["jurisdiction_tier"],
                "public_key":        vp_keypair["publicKey"],
                "status":            "active",
                "registered_at":     _utc_now(),
            }

    lbl("VP ID",  vp_record["vp_id"])
    lbl("Status", vp_record.get("status", "active"))
    return vp_record, vp_keypair


# ─── Step 4: Genesis Ring ─────────────────────────────────────────────────────

def step4_genesis_ring(
    vp_record: dict, vp_keypair: dict, node_url: str | None, direct: bool
) -> list[dict]:
    sep("STEP 4: Creating Genesis Ring (Founding Identities)")

    members = [
        {"name": "Dinesh Mendhe — Founder",      "role": "Founder & Sole Inventor",                        "region": "US", "tag": "founder"},
        {"name": "The AI Lab — Protocol Bot",     "role": "Automated VP credential for testing",            "region": "US", "tag": "system"},
        {"name": "Test Journalist",               "role": "Sample founding journalist (replace before launch)", "region": "US", "tag": "journalist"},
        {"name": "Test Researcher",               "role": "Sample founding researcher (replace before launch)", "region": "US", "tag": "researcher"},
    ]
    identities = []

    for m in members:
        kp        = generate_mldsa_keypair()
        root_kp   = generate_slhdsa_keypair()
        pepper    = generate_pepper()
        tip_id    = generate_tip_id(m["region"], kp["publicKey"])
        mock_hash = shake256_multi("seed", m["name"], m["region"], pepper)
        zk_proof  = compute_zk_proof(mock_hash)

        if direct or not node_url:
            reg_result = {
                "tip_id":           tip_id,
                "public_key":       kp["publicKey"],
                "private_key":      kp["privateKey"],
                "root_public_key":  root_kp["publicKey"],
                "root_private_key": root_kp["privateKey"],
                "score":            550,
                "registered_at":    _utc_now(),
                "vp_id":            vp_record["vp_id"],
            }
        else:
            try:
                # VP signs: dedup_hash + verification_tier + vp_id
                vp_payload   = mock_hash + "T1" + vp_record["vp_id"]
                vp_signature = mldsa_sign(vp_payload, vp_keypair["privateKey"])

                reg_result = _post(f"{node_url}/v1/identity/register", {
                    "region":            m["region"],
                    "vp_id":             vp_record["vp_id"],
                    "vp_signature":      vp_signature,
                    "dedup_hash":        mock_hash,
                    "zk_proof":          zk_proof,
                    "verification_tier": "T1",
                    "social_attested":   True,
                    "founding":          True,
                })
            except Exception as exc:
                warn(f"API registration failed for {m['name']}: {exc}")
                reg_result = {
                    "tip_id": tip_id, "public_key": kp["publicKey"],
                    "private_key": kp["privateKey"], "score": 550,
                    "registered_at": _utc_now(),
                }

        identity = {
            "tag":             m["tag"],
            "name":            m["name"],
            "role":            m["role"],
            "tip_id":          reg_result.get("tip_id", tip_id),
            "public_key":      kp["publicKey"],
            "private_key":     kp["privateKey"],
            "root_public_key": root_kp["publicKey"],
            "founding":        True,
            "score":           reg_result.get("score", 550),
            "registered_at":   reg_result.get("registered_at", _utc_now()),
        }
        identities.append(identity)

        ok(f"  {BOLD}{m['name']}{R}")
        lbl("    TIP-ID",  identity["tip_id"])
        lbl("    Score",   f"{identity['score']} / 1000 ({get_tier(identity['score']).label})")
        lbl("    Role",    m["role"])

    info(f"Genesis Ring: {len(identities)} founding members created")
    return identities


# ─── Step 5: Sample content ───────────────────────────────────────────────────

def step5_sample_content(
    identities: list[dict], node_url: str | None, direct: bool
) -> list[dict]:
    sep("STEP 5: Registering Sample Content (All Origin Types)")

    author = next((i for i in identities if i["tag"] == "founder"), None)
    if not author:
        warn("No founder identity found — skipping content registration")
        return []

    samples = [
        {
            "origin": Origin.OH,
            "title":  "TIP™ Protocol — Why the Internet Needs a Trust Layer",
            "content": (
                "The internet was built without an identity layer. HTTP, TCP/IP, DNS, and TLS "
                "solve routing, delivery, naming, and encryption. But none of them answer the "
                "fundamental question: who created this content, and can I trust it? This was "
                "an acceptable gap when content creation required skill and equipment. It is an "
                "existential gap now that AI can generate indistinguishable text, images, video, "
                "and audio at near-zero marginal cost. TIP™ is the protocol layer that closes this gap."
            ),
        },
        {
            "origin": Origin.AA,
            "title":  "AI-Assisted: Post-Quantum Cryptography Overview",
            "content": (
                "Post-quantum cryptography refers to cryptographic algorithms secure against "
                "attacks by quantum computers. The NIST PQC standardisation process has selected "
                "ML-DSA-65 (Dilithium), SLH-DSA-128s (SPHINCS+), and ML-KEM-768 (Kyber). "
                "TIP™ mandates these at the protocol level for long-term security. "
                "[Drafted by the author and expanded with AI assistance for clarity.]"
            ),
        },
        {
            "origin": Origin.AG,
            "title":  "AI-Generated: Frequently Asked Questions about TIP™",
            "content": (
                "Q: What is TIP™? A: An open, federated protocol for verifying human identity "
                "and declaring content provenance. Q: Is TIP™ free? A: Yes — the spec is CC-BY 4.0. "
                "Q: How does the trust score work? A: Scores are computed deterministically from "
                "your complete transaction history on the federated DAG. "
                "[Generated entirely by AI from the protocol specification.]"
            ),
        },
        {
            "origin": Origin.MX,
            "title":  "Mixed: TIP™ Launch Announcement",
            "content": (
                "[Human-written announcement] We are pleased to announce TIP™ Protocol v2.0. "
                "[AI-generated technical summary] This release includes five critical security fixes "
                "addressing privacy architecture, pre-scan calibration, identity revocation, GDPR "
                "compliance, and jurisdiction tier enforcement. "
                "[Human-written conclusion] We invite developers, journalists, and researchers to "
                "implement TIP™ and join the founding network."
            ),
        },
    ]

    registered = []
    for s in samples:
        content_hash = hash_content(s["content"])
        ctid         = generate_ctid(s["origin"], content_hash, author["tip_id"])
        sig_payload  = content_hash + s["origin"]
        signature    = mldsa_sign(sig_payload, author["private_key"])

        if direct or not node_url:
            result = {
                "ctid":          ctid,
                "origin_code":   s["origin"],
                "origin_label":  Origin.label(s["origin"]),
                "content_hash":  content_hash,
                "author_tip_id": author["tip_id"],
                "status":        "verified",
                "registered_at": _utc_now(),
            }
        else:
            try:
                result = _post(f"{node_url}/v1/content/register", {
                    "author_tip_id": author["tip_id"],
                    "origin_code":   s["origin"],
                    "content":       s["content"],
                    "content_hash":  content_hash,
                    "signature":     signature,
                })
            except Exception as exc:
                warn(f"Content registration failed for {s['origin']}: {exc}")
                result = {"ctid": ctid, "origin_code": s["origin"], "status": "local-only"}

        registered.append({**s, "ctid": result.get("ctid", ctid), "status": result.get("status")})
        ok(f"  {BOLD}{Origin.label(s['origin'])}{R} — {s['title'][:50]}...")
        lbl("    CTID",    result.get("ctid", ctid))
        lbl("    Status",  result.get("status", "unknown"))

    return registered


# ─── Step 6: DAG verification ─────────────────────────────────────────────────

def step6_verify(
    genesis_block: dict, vp_record: dict, identities: list, content: list,
    node_url: str | None, direct: bool
) -> bool:
    sep("STEP 6: DAG State Verification")

    checks = []
    expected = _compute_genesis_hash()
    checks.append(("Genesis block hash",           genesis_block.get("genesis_hash") == expected, genesis_block.get("genesis_hash", "")[:32] + "..."))
    checks.append(("Genesis signature present",    bool(genesis_block.get("signature")),          (genesis_block.get("signature") or "")[:24] + "..."))
    checks.append(("Chain ID correct",             genesis_block.get("protocol", {}).get("chain_id") == GENESIS_CHAIN_ID, GENESIS_CHAIN_ID))
    checks.append(("Founding VP registered",       bool(vp_record and vp_record.get("vp_id")),    vp_record.get("vp_id", "MISSING")))
    checks.append(("Genesis ring size >= 2",       len(identities) >= 2,                          f"{len(identities)} founding members"))
    checks.append(("All four origin types",        len(content) == 4,                             ", ".join(c["origin"] for c in content)))
    checks.append(("TIP-ID format valid",          all("tip://id/" in i["tip_id"] for i in identities), "All valid" if all("tip://id/" in i["tip_id"] for i in identities) else "INVALID"))

    import re
    ctid_re = re.compile(r"^tip://c/(OH|AA|AG|MX)-[0-9a-f]{14}-[0-9a-f]{4}$")
    valid_ctids = all(ctid_re.match(c.get("ctid", "")) for c in content if c.get("ctid"))
    checks.append(("CTID format valid",            valid_ctids, "All valid" if valid_ctids else "INVALID"))

    if not direct and node_url:
        try:
            h = _get(f"{node_url}/health")
            checks.append(("Node health",   h.get("status") == "ok", f"DAG txs: {h.get('dag_count')}"))
        except Exception as exc:
            checks.append(("Node health",   False, str(exc)))

    print()
    all_pass = True
    for name, passed, detail in checks:
        icon  = f"{GRN}✓{R}" if passed else f"{RED}✗{R}"
        print(f"  {icon} {name:<40} {DIM}{detail}{R}")
        if not passed:
            all_pass = False
    print()
    return all_pass


# ─── Step 7: Write output ─────────────────────────────────────────────────────

def step7_write_output(
    data_dir: pathlib.Path,
    genesis_block: dict,
    vp_record: dict,
    vp_keypair: dict,
    identities: list,
    content: list,
) -> dict:
    sep("STEP 7: Writing Seed Output")

    output = {
        "seed_version": "2.0.0",
        "created_at":   _utc_now(),
        "environment":  os.environ.get("TIP_ENV", "development"),
        "genesis": {
            "hash":      genesis_block.get("genesis_hash"),
            "chain_id":  GENESIS_CHAIN_ID,
            "timestamp": GENESIS_TIMESTAMP,
            "signer_pk": genesis_block.get("signer_public_key"),
        },
        "founding_vp": {
            "vp_id":             vp_record["vp_id"],
            "name":              vp_record["name"],
            "jurisdiction_tier": vp_record.get("jurisdiction_tier"),
            "public_key":        vp_record.get("public_key"),
        },
        "genesis_ring": [
            {
                "tag": i["tag"], "name": i["name"], "role": i["role"],
                "tip_id": i["tip_id"], "founding": True, "score": i["score"],
            }
            for i in identities
        ],
        "sample_content": [
            {"origin": c["origin"], "origin_label": Origin.label(c["origin"]),
             "title": c["title"], "ctid": c["ctid"], "status": c["status"]}
            for c in content
        ],
    }
    seed_file = data_dir / "seed-output.json"
    seed_file.write_text(json.dumps(output, indent=2))
    ok(f"Seed output written to: {seed_file}")

    # Write private keys to a separate secure file
    keys_out = {
        "created_at":      _utc_now(),
        "security_notice": "HIGHLY SENSITIVE. Keep offline. Never commit to version control.",
        "genesis_ring_keys": [
            {"tag": i["tag"], "name": i["name"], "tip_id": i["tip_id"],
             "private_key": i["private_key"], "public_key": i["public_key"]}
            for i in identities
        ],
        "vp_private_key": vp_keypair["privateKey"],
        "vp_public_key":  vp_keypair["publicKey"],
    }
    keys_file = data_dir / "founder-keys.json"
    keys_file.write_text(json.dumps(keys_out, indent=2))
    try:
        os.chmod(keys_file, 0o600)
    except AttributeError:
        pass
    ok(f"Founder keys written to: {keys_file} (chmod 600)")
    warn("SECURITY: Add genesis-data/ private key files to .gitignore")
    return output


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="TIP™ Protocol Production Seed Script v2.0",
    )
    parser.add_argument("--genesis-keys-only", action="store_true",
                        help="Only generate genesis root keypair (step 1)")
    parser.add_argument("--node-url",  default=None,
                        help="TIP node URL for API mode (default: direct mode)")
    parser.add_argument("--data-dir",  default=None,
                        help="Data directory (default: node/genesis-data/)")
    args = parser.parse_args()

    direct   = args.node_url is None
    node_url = args.node_url

    base_dir = pathlib.Path(__file__).parent.parent
    data_dir = pathlib.Path(args.data_dir) if args.data_dir else (
        base_dir / "node" / "genesis-data"
    )

    print()
    print(f"{BGNAVY}{WHT}{BOLD}  TIP™ Protocol — Production Seed Script v2.0  {R}")
    print(f"{DIM}  The AI Lab Intelligence Unobscured, Inc. | theailab.org{R}")
    print()
    info(f"Mode:     {'Direct (no HTTP)' if direct else f'API ({node_url})'}")
    info(f"Data dir: {data_dir}")
    print()

    try:
        root_keys = step1_genesis_keys(data_dir)
        if args.genesis_keys_only:
            ok("Genesis keys generated. Run without --genesis-keys-only to continue.")
            return

        genesis_block       = step2_genesis_block(data_dir, root_keys)
        vp_record, vp_kp    = step3_founding_vp(genesis_block, node_url, direct)
        identities          = step4_genesis_ring(vp_record, vp_kp, node_url, direct)
        content             = step5_sample_content(identities, node_url, direct)
        all_pass            = step6_verify(genesis_block, vp_record, identities, content, node_url, direct)
        output              = step7_write_output(data_dir, genesis_block, vp_record, vp_kp, identities, content)

        sep("SEED COMPLETE")
        lbl("Genesis hash",          output["genesis"]["hash"][:48] + "...")
        lbl("Chain ID",              output["genesis"]["chain_id"])
        lbl("Founding VP",           output["founding_vp"]["vp_id"])
        lbl("Genesis ring members",  str(len(output["genesis_ring"])))
        lbl("Sample content",        f"{len(output['sample_content'])} records (OH, AA, AG, MX)")
        lbl("Validation",            f"{GRN}All checks passed{R}" if all_pass else f"{RED}Some checks failed{R}")
        print()
        ok(f"{BOLD}TIP™ Protocol genesis complete.{R}")
        print()

        if not all_pass:
            sys.exit(1)

    except Exception as exc:
        print(f"\n{RED}{BOLD}SEED FAILED:{R} {exc}")
        sys.exit(1)


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    main()
