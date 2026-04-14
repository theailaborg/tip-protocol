"""
cli/main.py
TIP Protocol Python CLI

Usage:
  python -m cli.main --help
  python -m cli.main config set-node http://localhost:4000
  python -m cli.main identity register --vp-id tip://vp/... --region US
  python -m cli.main identity score tip://id/US-...
  python -m cli.main content register --file article.txt --origin OH
  python -m cli.main badge seal --score 892 --out seal.svg
  python -m cli.main node ping

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import click
from shared.crypto import (
    generate_mldsa_keypair, mldsa_sign, generate_tip_id,
    shake256, shake256_multi,
    compute_zk_proof,
)
from shared.constants import Origin, get_tier, Protocol

_CONFIG_FILE = pathlib.Path.home() / ".tip-cli.json"
G = "\x1b[32m"; Y = "\x1b[33m"; C = "\x1b[36m"; R = "\x1b[0m"; D = "\x1b[2m"; B = "\x1b[1m"


def _load_cfg() -> dict:
    try:
        return json.loads(_CONFIG_FILE.read_text())
    except Exception:
        return {}


def _save_cfg(cfg: dict) -> None:
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def _get_client():
    from sdk.client import TIPClient
    cfg = _load_cfg()
    url = cfg.get("node_url") or os.environ.get("TIP_NODE_URL") or "http://localhost:4000"
    return TIPClient(node_url=url)


def _print_score(data: dict) -> None:
    score = data.get("score", 0)
    tier  = get_tier(score)
    color = G if score >= 800 else C if score >= 600 else Y if score >= 400 else "\x1b[31m"
    click.echo(f"\n  {B}Trust Score{R}")
    if "score" in data:
        click.echo(f"  {'Score':<24} {color}{B}{score}{R} / 1000")
    click.echo(f"  {'Tier':<24} {color}{data.get('tier_label', tier.label)}{R}")
    if data.get("verified_since"):
        click.echo(f"  {'Verified since':<24} {D}{data['verified_since']}{R}")
    if data.get("content_count") is not None:
        click.echo(f"  {'Content count':<24} {data['content_count']}")
    if data.get("status"):
        click.echo(f"  {'Status':<24} {data['status']}")
    click.echo()


# ─── Root group ───────────────────────────────────────────────────────────────

@click.group()
@click.version_option("2.0.0", prog_name="tip")
def cli():
    """TIP™ Protocol CLI v2.0 — Trust Identity Protocol\n\nThe AI Lab Intelligence Unobscured, Inc. | theailab.org"""


# ─── CONFIG ───────────────────────────────────────────────────────────────────

@cli.group()
def config():
    """Manage CLI configuration."""


@config.command("set-node")
@click.argument("url")
def config_set_node(url):
    """Set the TIP node URL."""
    cfg = _load_cfg(); cfg["node_url"] = url; _save_cfg(cfg)
    click.echo(f"{G}✓{R} Node URL set to: {url}")


@config.command("set-identity")
@click.argument("tip_id")
def config_set_identity(tip_id):
    """Set your default TIP-ID."""
    cfg = _load_cfg(); cfg["default_tip_id"] = tip_id; _save_cfg(cfg)
    click.echo(f"{G}✓{R} Default TIP-ID set to: {tip_id}")


@config.command("set-key")
@click.argument("hex_key")
def config_set_key(hex_key):
    """Store your ML-DSA-65 private key locally."""
    cfg = _load_cfg(); cfg["private_key"] = hex_key; _save_cfg(cfg)
    click.echo(f"{G}✓{R} Private key stored.")
    click.echo(f"{Y}⚠{R} Keep {_CONFIG_FILE} secure. Never commit it to version control.")


@config.command("show")
def config_show():
    """Show current configuration."""
    cfg = _load_cfg()
    click.echo(f"\n  {B}TIP CLI Configuration{R}")
    click.echo(f"  {'Node URL':<24} {cfg.get('node_url') or '(not set — default: http://localhost:4000)'}")
    click.echo(f"  {'Default TIP-ID':<24} {cfg.get('default_tip_id') or '(not set)'}")
    click.echo(f"  {'Private key':<24} {'[stored]' if cfg.get('private_key') else '(not set)'}")
    click.echo(f"  {'Config file':<24} {_CONFIG_FILE}")
    click.echo()


# ─── IDENTITY ─────────────────────────────────────────────────────────────────

@cli.group()
def identity():
    """Identity management."""


@identity.command("generate-keypair")
def identity_generate_keypair():
    """Generate a new ML-DSA-65 keypair (local only, not registered)."""
    kp = generate_mldsa_keypair()
    click.echo(f"\n  {B}New ML-DSA-65 Keypair{R}")
    click.echo(f"  {'Algorithm':<24} {kp['algorithm']}")
    click.echo(f"  {'Public key (first 32)':<24} {kp['publicKey'][:32]}...")
    click.echo(f"\n{Y}  ℹ{R} Run: tip config set-key <privateKey>  to store locally")
    click.echo(f"\n{D}  Full public key:{R}\n  {kp['publicKey']}")
    click.echo(f"\n{D}  Full private key:{R}\n  {kp['privateKey']}\n")


@identity.command("register")
@click.option("--vp-id",   required=True,  help="Verification Provider ID")
@click.option("--vp-key",  required=True,  help="VP private key (hex) for signing the registration")
@click.option("--region",  default="US",   help="Region code (default: US)")
@click.option("--tier",    default="T1",   help="Verification tier T1-T4 (default: T1)")
@click.option("--attested", is_flag=True,  help="Has social attestation (3 vouchers)")
@click.option("--founding", is_flag=True,  help="Founding member (Genesis Ring)")
def identity_register(vp_id, vp_key, region, tier, attested, founding):
    """[DEV ONLY] Register a TIP-ID with mock ZK proof (production: use VP SDK)."""
    client = _get_client()
    # CLI uses a mock dedup_hash and zk_proof — real flow requires the VP SDK
    # running generateDedupProof(govId, dob, country) on the user's device (shared/zk.js).
    mock_dedup_hash = shake256_multi("cli-registration", region, vp_id)
    mock_zk_proof   = {"pi_a": ["1","2","3"], "pi_b": [["1","2"],["3","4"],["5","6"]], "pi_c": ["1","2","3"], "protocol": "groth16", "curve": "bn128"}

    # VP signs: dedup_hash + verification_tier + vp_id
    vp_payload   = mock_dedup_hash + tier + vp_id
    vp_signature = mldsa_sign(vp_payload, vp_key)

    click.echo(f"\n  Registering TIP-ID...")
    click.echo(f"  {'Region':<20} {region}")
    click.echo(f"  {'VP ID':<20} {vp_id}")
    click.echo(f"  {'Tier':<20} {tier}")

    try:
        res = client.identity.register(
            vp_id=vp_id, vp_signature=vp_signature,
            dedup_hash=mock_dedup_hash, zk_proof=mock_zk_proof,
            region=region, verification_tier=tier,
            social_attested=attested, founding=founding,
        )
        click.echo(f"\n  {G}{B}Identity registered!{R}\n")
        click.echo(f"  {'TIP-ID':<24} {res['tip_id']}")
        click.echo(f"  {'Score':<24} {res['score']}")
        click.echo(f"  {'TX ID':<24} {res['tx_id']}")
        click.echo(f"\n  {Y}{B}IMPORTANT: Save your private key now.{R}")
        click.echo(f"  {res['private_key']}")
        click.echo(f"\n  {C}ℹ{R} Run: tip config set-key <key>  to store it locally")
        click.echo(f"  {C}ℹ{R} Run: tip config set-identity {res['tip_id']}")
    except Exception as exc:
        click.echo(f"\n  {R if True else ''}Registration failed: {exc}", err=True)
        sys.exit(1)


@identity.command("resolve")
@click.argument("tip_id")
def identity_resolve(tip_id):
    """Resolve a TIP-ID to its public record."""
    try:
        res = _get_client().identity.resolve(tip_id)
        click.echo(f"\n  {B}Identity Record{R}")
        for k, v in [("TIP-ID", res.get("tip_id")), ("Region", res.get("region")),
                     ("VP", res.get("vp_id")), ("Tier", res.get("verification_tier")),
                     ("Status", res.get("status")), ("Founding", "Yes ★" if res.get("founding") else "No"),
                     ("Content count", res.get("content_count")), ("Registered at", res.get("registered_at"))]:
            click.echo(f"  {str(k):<24} {v}")
        _print_score(res)
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@identity.command("score")
@click.argument("tip_id")
def identity_score(tip_id):
    """Get trust score for a TIP-ID."""
    try:
        _print_score(_get_client().trust.get_score(tip_id))
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@identity.command("history")
@click.argument("tip_id")
def identity_history(tip_id):
    """Show full score history for a TIP-ID."""
    try:
        res = _get_client().identity.get_history(tip_id)
        click.echo(f"\n  {B}Score History: {tip_id}{R}\n")
        history = res.get("history", [])
        if not history:
            click.echo(f"  {C}ℹ{R} No score events found.")
        else:
            for ev in history:
                delta = ev.get("delta", 0)
                sign  = f"{G}+{delta}{R}" if delta >= 0 else f"\x1b[31m{delta}{R}"
                click.echo(
                    f"  {D}{ev.get('timestamp','')[:19]}{R}  "
                    f"{sign:<20}  {str(ev.get('score_after',0)):>5} pts  "
                    f"{D}{ev.get('reason','')}{R}"
                )
        click.echo()
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


# ─── CONTENT ──────────────────────────────────────────────────────────────────

@cli.group()
def content():
    """Content provenance management."""


@content.command("register")
@click.option("--file",   "file_path",  default=None, help="Path to content file")
@click.option("--text",   default=None, help="Inline content text")
@click.option("--hash",   "content_hash", default=None, help="Pre-computed content hash")
@click.option("--origin", required=True,  help="Origin code: OH | AA | AG | MX")
@click.option("--tip-id", default=None,   help="Author TIP-ID (uses default if set)")
@click.option("--key",    default=None,   help="ML-DSA-65 private key (uses config if set)")
def content_register(file_path, text, content_hash, origin, tip_id, key):
    """Register content with a mandatory origin declaration."""
    cfg     = _load_cfg()
    tip_id  = tip_id or cfg.get("default_tip_id")
    priv_key = key or cfg.get("private_key")

    if not tip_id:
        click.echo("  Error: --tip-id required (or set default: tip config set-identity <id>)", err=True); sys.exit(1)
    if not Origin.is_valid(origin):
        click.echo(f"  Error: Invalid --origin. Must be one of: {', '.join(Origin.ALL)}", err=True); sys.exit(1)

    body = None
    if file_path:
        try:
            body = pathlib.Path(file_path).read_text()
        except OSError as exc:
            click.echo(f"  Error reading file: {exc}", err=True); sys.exit(1)
    else:
        body = text

    if not body and not content_hash:
        click.echo("  Error: --file, --text, or --hash required", err=True); sys.exit(1)

    click.echo(f"\n  Registering content...")
    click.echo(f"  {'Author':<20} {tip_id}")
    click.echo(f"  {'Origin':<20} {origin} ({Origin.label(origin)})")
    if file_path:
        click.echo(f"  {'File':<20} {file_path} ({len(body or '')} chars)")

    try:
        res = _get_client().content.register(
            author_tip_id=tip_id, origin_code=origin,
            content=body, content_hash=content_hash, private_key=priv_key,
        )
        click.echo(f"\n  {G}{B}Content registered!{R}\n")
        click.echo(f"  {'CTID':<24} {res.get('ctid')}")
        click.echo(f"  {'Origin':<24} {res.get('origin_code')} — {res.get('origin_label')}")
        click.echo(f"  {'Content hash':<24} {res.get('content_hash')}")
        click.echo(f"  {'Status':<24} {res.get('status')}")
        if res.get("prescan_flagged"):
            click.echo(f"\n  {Y}⚠ Pre-scan flagged:{R} {res.get('prescan_note')}")
        click.echo(f"\n  {D}Nginx config:{R}")
        click.echo(res.get("nginx_snippet", ""))
        click.echo(f"\n  {D}HTML meta tags:{R}")
        click.echo(res.get("html_snippet", ""))
        click.echo()
    except Exception as exc:
        click.echo(f"\n  Content registration failed: {exc}", err=True); sys.exit(1)


@content.command("resolve")
@click.argument("ctid")
def content_resolve(ctid):
    """Resolve a CTID to its provenance record."""
    try:
        res = _get_client().content.resolve(ctid)
        click.echo(f"\n  {B}Content Record{R}")
        for k, v in [("CTID", res.get("ctid")), ("Origin", f"{res.get('origin_code')} — {res.get('origin_label', '')}"),
                     ("Author", res.get("author_tip_id")), ("Status", res.get("status")),
                     ("Disputes", res.get("dispute_count")), ("Verifications", res.get("verification_count")),
                     ("Registered at", res.get("registered_at"))]:
            click.echo(f"  {str(k):<24} {v}")
        click.echo()
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@content.command("verify")
@click.argument("ctid")
@click.option("--as", "verifier_id", default=None, help="Verifier TIP-ID (uses default if set)")
def content_verify(ctid, verifier_id):
    """Submit a community verification of content origin."""
    cfg = _load_cfg()
    vid = verifier_id or cfg.get("default_tip_id")
    if not vid:
        click.echo("  Error: --as <tipId> required", err=True); sys.exit(1)
    try:
        res = _get_client().content.verify(ctid, vid)
        click.echo(f"  {G}✓{R} Verification submitted. Score delta: +{res.get('delta_applied', 0)}")
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@content.command("dispute")
@click.argument("ctid")
@click.option("--as",       "disputer_id", required=True,  help="Disputer TIP-ID")
@click.option("--reason",   required=True,  help="Reason for dispute")
@click.option("--evidence", default=None,   help="Evidence hash")
def content_dispute(ctid, disputer_id, reason, evidence):
    """File an origin dispute against a content record."""
    try:
        res = _get_client().content.dispute(ctid, disputer_id, reason, evidence)
        click.echo(f"  {G}✓{R} {res.get('message')}")
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


# ─── TRUST ────────────────────────────────────────────────────────────────────

@cli.group()
def trust():
    """Trust scoring and revocations."""


@trust.command("score")
@click.argument("tip_id")
def trust_score(tip_id):
    """Get trust score for a TIP-ID."""
    try:
        _print_score(_get_client().trust.get_score(tip_id))
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@trust.command("revocations")
@click.option("--since", default=None, help="Only show revocations after this ISO timestamp")
def trust_revocations(since):
    """List recent revocations."""
    try:
        res = _get_client().trust.get_revocations(since)
        click.echo(f"\n  {B}Revocations ({res.get('count', 0)}){R}\n")
        for r in res.get("revocations", []):
            click.echo(f"  \x1b[31m{r.get('tip_id')}{R}  {D}{r.get('tx_type')} · {r.get('timestamp')}{R}")
        if not res.get("revocations"):
            click.echo(f"  {C}ℹ{R} No revocations found.")
        click.echo()
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@trust.command("merkle-root")
def trust_merkle_root():
    """Get the dedup Merkle root for public audit."""
    try:
        res = _get_client().trust.get_merkle_root()
        click.echo(f"\n  {B}Dedup Merkle Root{R}")
        for k, v in [("Merkle root", res.get("merkle_root")), ("Dedup count", res.get("dedup_count")),
                     ("Identity count", res.get("identity_count")), ("Generated", res.get("generated"))]:
            click.echo(f"  {str(k):<24} {v}")
        click.echo()
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


# ─── VP ───────────────────────────────────────────────────────────────────────

@cli.group()
def vp():
    """Verification Provider management."""


@vp.command("register")
@click.option("--name",  required=True,  help="VP display name")
@click.option("--tier",  default="green", help="Jurisdiction tier: green|amber (default: green)")
@click.option("--key",   default=None,   help="VP public key (generates if omitted)")
def vp_register(name, tier, key):
    """Register a new Verification Provider."""
    pub_key = key
    if not pub_key:
        kp = generate_mldsa_keypair()
        pub_key = kp["publicKey"]
        click.echo(f"  {C}ℹ{R} Generated VP keypair. Private key (save securely):")
        click.echo(f"  {kp['privateKey']}")
    try:
        res = _get_client().register_vp(name, pub_key, tier)
        click.echo(f"  {G}✓{R} VP registered: {res.get('vp_id')}")
        click.echo(f"  {'Name':<20} {res.get('name')}")
        click.echo(f"  {'Tier':<20} {res.get('jurisdiction_tier')}")
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


@vp.command("resolve")
@click.argument("vp_id")
def vp_resolve(vp_id):
    """Resolve a VP record."""
    try:
        res = _get_client().resolve_vp(vp_id)
        click.echo(f"\n  {B}Verification Provider{R}")
        for k, v in res.items():
            click.echo(f"  {str(k):<24} {v}")
        click.echo()
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


# ─── NODE ─────────────────────────────────────────────────────────────────────

@cli.group()
def node():
    """Node diagnostics."""


@node.command("info")
def node_info():
    """Show node information."""
    try:
        res = _get_client().node_info()
        click.echo(f"\n  {B}TIP Node Info{R}")
        for k, v in res.items():
            click.echo(f"  {str(k):<28} {v}")
        click.echo()
    except Exception as exc:
        click.echo(f"  {R}Could not reach node: {exc}", err=True); sys.exit(1)


@node.command("ping")
def node_ping():
    """Check node health."""
    cfg = _load_cfg()
    url = cfg.get("node_url") or "http://localhost:4000"
    click.echo(f"  {C}ℹ{R} Pinging {url}...")
    try:
        res = _get_client().ping()
        click.echo(f"  {G}✓{R} Node healthy. DAG transactions: {res.get('dag_count')}")
    except Exception as exc:
        click.echo(f"  {R}Node unreachable: {exc}", err=True); sys.exit(1)


@node.command("peers")
def node_peers():
    """Show connected peers."""
    try:
        res = _get_client().peers()
        click.echo(f"\n  {B}Peers ({res.get('count', 0)}){R}\n")
        for p in res.get("peers", []):
            click.echo(f"  {C}ℹ{R} {p}")
        if not res.get("peers"):
            click.echo(f"  No peers connected.")
        click.echo()
    except Exception as exc:
        click.echo(f"  Error: {exc}", err=True); sys.exit(1)


# ─── BADGE ────────────────────────────────────────────────────────────────────

@cli.group()
def badge():
    """Badge generation (SVG)."""


@badge.command("seal")
@click.option("--score",    required=True,  type=int, help="Trust score 0-1000")
@click.option("--size",     default=200,    type=int, help="Size in pixels (default: 200)")
@click.option("--variant",  default="gold-dark", help="gold-dark | light | dark")
@click.option("--founding", is_flag=True,   help="Show founding star")
@click.option("--out",      default=None,   help="Output file (stdout if omitted)")
def badge_seal(score, size, variant, founding, out):
    """Generate an AI Trust ID™ Seal SVG."""
    from sdk.client import TIPBadgesClient
    svg = TIPBadgesClient().render_seal(score, size, variant, founding)
    if out:
        pathlib.Path(out).write_text(svg)
        click.echo(f"  {G}✓{R} Seal written to: {out}")
    else:
        click.echo(svg)


@badge.command("mark")
@click.option("--size",    default=140, type=int, help="Size in pixels (default: 140)")
@click.option("--variant", default="light", help="light | dark")
@click.option("--out",     default=None, help="Output file")
def badge_mark(size, variant, out):
    """Generate a TIP™ Powered Mark SVG (open, Apache 2.0)."""
    from sdk.client import TIPBadgesClient
    svg = TIPBadgesClient().render_tip_mark(size, variant)
    if out:
        pathlib.Path(out).write_text(svg)
        click.echo(f"  {G}✓{R} TIP mark written to: {out}")
    else:
        click.echo(svg)


@badge.command("shield")
@click.option("--score",    required=True, type=int, help="Trust score 0-1000")
@click.option("--size",     default=48,   type=int)
@click.option("--founding", is_flag=True)
@click.option("--out",      default=None)
def badge_shield(score, size, founding, out):
    """Generate an inline shield badge SVG."""
    from sdk.client import TIPBadgesClient
    svg = TIPBadgesClient().render_shield(score, size, founding)
    if out:
        pathlib.Path(out).write_text(svg)
        click.echo(f"  {G}✓{R} Shield written to: {out}")
    else:
        click.echo(svg)


@badge.command("headers")
@click.option("--tip-id",  required=True)
@click.option("--ctid",    required=True)
@click.option("--origin",  required=True)
@click.option("--score",   required=True, type=int)
@click.option("--sig",     default=None)
@click.option("--format",  "fmt", default="nginx", help="nginx|apache|caddy|cloudflare|netlify")
def badge_headers(tip_id, ctid, origin, score, sig, fmt):
    """Generate HTTP header config for your web server."""
    from sdk.client import TIPBadgesClient
    cfg = TIPBadgesClient().generate_http_config(tip_id, ctid, origin, score, sig or "[ML-DSA-65 signature]")
    click.echo(f"\n  {B}{fmt.upper()} Configuration{R}\n")
    click.echo(cfg.get(fmt, cfg["nginx"]))
    click.echo(f"\n  {D}HTML meta tags:{R}")
    click.echo(TIPBadgesClient().generate_meta_tags(tip_id, ctid, origin, score))
    click.echo()


if __name__ == "__main__":
    cli()
