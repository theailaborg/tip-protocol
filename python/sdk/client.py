"""
sdk/client.py
TIP Protocol Python SDK

Usage:
    from sdk.client import TIPClient

    tip = TIPClient(node_url="http://localhost:4000")
    await tip.ping()  # sync; also supports async with aiohttp if available

    # Register identity
    identity = tip.identity.register(
        region="US", vp_id="tip://id/VP-US-...",
        zk_dedup_proof="zkp:..."
    )

    # Register content
    content = tip.content.register(
        author_tip_id=identity["tip_id"],
        private_key=identity["private_key"],
        origin_code="OH",
        content="My article text...",
    )

    # Query score
    score = tip.trust.get_score(identity["tip_id"])

    # Generate badge SVG
    svg = tip.badges.render_seal(score=score["score"], variant="gold-dark")

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from shared.crypto import (
    generate_mldsa_keypair, generate_slhdsa_keypair,
    generate_tip_id, generate_ctid,
    hash_content, perceptual_hash_text,
    mldsa_sign, verify_tx_signature,
    sign_transaction, generate_pepper,
    compute_zk_proof, compute_zk_score_proof, verify_zk_score_proof,
    shake256, shake256_multi,
)
from shared.constants import (
    Origin, get_tier, HttpHeaders, Protocol, Tier,
    ScoreEvent,
)


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

class TIPHTTPError(Exception):
    def __init__(self, status: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.status  = status
        self.message = message
        self.data    = data


def _request(node_url: str, path: str, method: str = "GET",
             body: Optional[dict] = None, timeout: int = 10,
             api_key: Optional[str] = None) -> dict:
    url     = node_url.rstrip("/") + path
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["X-TIP-API-Key"] = api_key

    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            data = json.loads(exc.read().decode())
        except Exception:
            data = {}
        raise TIPHTTPError(exc.code, data.get("error", f"HTTP {exc.code}"), data) from exc
    except urllib.error.URLError as exc:
        raise TIPHTTPError(0, f"Connection failed: {exc.reason}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# IDENTITY CLIENT
# ══════════════════════════════════════════════════════════════════════════════

class TIPIdentityClient:
    def __init__(self, node_url: str, timeout: int = 10, api_key: Optional[str] = None):
        self._url     = node_url
        self._timeout = timeout
        self._api_key = api_key

    def _get(self, path: str) -> dict:
        return _request(self._url, path, timeout=self._timeout, api_key=self._api_key)

    def _post(self, path: str, body: dict) -> dict:
        return _request(self._url, path, "POST", body, self._timeout, self._api_key)

    # ── Local (no network) ────────────────────────────────────────────────────

    def generate_keypair(self) -> dict:
        """Generate ML-DSA-65 + SLH-DSA-128s keypairs locally."""
        primary = generate_mldsa_keypair()
        root    = generate_slhdsa_keypair()
        return {
            "publicKey":      primary["publicKey"],
            "privateKey":     primary["privateKey"],
            "rootPublicKey":  root["publicKey"],
            "rootPrivateKey": root["privateKey"],
            "algorithm":      "ML-DSA-65 + SLH-DSA-128s",
        }

    def generate_pepper(self) -> str:
        """Generate a 256-bit device-side pepper. NEVER send to server."""
        return generate_pepper()

    def compute_zk_proof(
        self,
        gov_id_normalized: str,
        date_of_birth_iso: str,
        country_code: str,
        facial_embedding_hash: str,
        pepper: str,
    ) -> str:
        """
        Compute ZK proof of uniqueness from biometric inputs + pepper.
        This runs on the user's device. The pepper and raw inputs
        NEVER leave the device.
        """
        from shared.crypto import compute_dedup_hash
        dedup_hash = compute_dedup_hash(
            gov_id_normalized, date_of_birth_iso,
            country_code, facial_embedding_hash, pepper,
        )
        return compute_zk_proof(dedup_hash)

    def compute_tip_id(self, region: str, public_key_hex: str) -> str:
        """Compute a TIP-ID URI from a public key (no network call)."""
        return generate_tip_id(region, public_key_hex)

    # ── Network ───────────────────────────────────────────────────────────────

    def register(
        self,
        vp_id: str,
        zk_dedup_proof: str,
        region: str = "US",
        verification_tier: str = "T1",
        social_attested: bool = False,
        founding: bool = False,
    ) -> dict:
        """
        Register a new TIP-ID on the node.
        Returns the identity record including private_key (store securely — never re-shown).
        """
        return self._post("/v1/identity/register", {
            "region":            region,
            "vp_id":             vp_id,
            "zk_dedup_proof":    zk_dedup_proof,
            "verification_tier": verification_tier,
            "social_attested":   social_attested,
            "founding":          founding,
        })

    def resolve(self, tip_id: str) -> dict:
        return self._get(f"/v1/identity/{urllib.parse.quote(tip_id, safe='')}")

    def get_score(self, tip_id: str) -> dict:
        return self._get(f"/v1/identity/{urllib.parse.quote(tip_id, safe='')}/score")

    def get_history(self, tip_id: str) -> dict:
        return self._get(f"/v1/identity/{urllib.parse.quote(tip_id, safe='')}/history")


# ══════════════════════════════════════════════════════════════════════════════
# CONTENT CLIENT
# ══════════════════════════════════════════════════════════════════════════════

class TIPContentClient:
    def __init__(self, node_url: str, timeout: int = 10, api_key: Optional[str] = None):
        self._url     = node_url
        self._timeout = timeout
        self._api_key = api_key

    def _get(self, path: str) -> dict:
        return _request(self._url, path, timeout=self._timeout, api_key=self._api_key)

    def _post(self, path: str, body: dict) -> dict:
        return _request(self._url, path, "POST", body, self._timeout, self._api_key)

    def hash_locally(self, content: str, origin_code: str = "OH") -> dict:
        """Hash content locally without a network call."""
        h = hash_content(content)
        ph = perceptual_hash_text(content)
        return {
            "content_hash":   h,
            "perceptual_hash": ph,
            "ctid_preview":   f"tip://c/{origin_code}-{h}-????",
        }

    def sign_content(self, content: str, origin_code: str, private_key: str) -> dict:
        """
        Sign a content registration locally.
        Signature covers (content_hash + origin_code) — origin is cryptographically
        inseparable from the content.
        """
        if not Origin.is_valid(origin_code):
            raise ValueError(f"Invalid origin_code '{origin_code}'. Must be OH, AA, AG, or MX")
        ch  = hash_content(content)
        sig = mldsa_sign(ch + origin_code, private_key)
        return {
            "content_hash": ch,
            "signature":    sig,
            "origin_code":  origin_code,
            "ctid_preview": f"tip://c/{origin_code}-{ch}-????",
        }

    def register(
        self,
        author_tip_id: str,
        origin_code: str,
        content: Optional[str] = None,
        content_hash: Optional[str] = None,
        private_key: Optional[str] = None,
    ) -> dict:
        """
        Register content on the node with a mandatory origin declaration.
        Returns CTID, HTTP header config, and HTML meta tag snippet.
        """
        if not content and not content_hash:
            raise ValueError("content or content_hash is required")
        if not Origin.is_valid(origin_code):
            raise ValueError(f"Invalid origin_code '{origin_code}'")

        ch        = content_hash or hash_content(content or "")
        payload   = ch + origin_code
        signature = mldsa_sign(payload, private_key) if private_key else "unsigned"

        res = self._post("/v1/content/register", {
            "author_tip_id": author_tip_id,
            "origin_code":   origin_code,
            "content":       content,
            "content_hash":  ch,
            "signature":     signature,
        })
        # Add convenience snippets
        if "http_headers" in res:
            res["nginx_snippet"]  = self.build_nginx_snippet(res["http_headers"])
            res["html_snippet"]   = self.build_meta_tags(res.get("meta_tags", {}))
        return res

    def resolve(self, ctid: str) -> dict:
        return self._get(f"/v1/content/{urllib.parse.quote(ctid, safe='')}")

    def verify(self, ctid: str, verifier_tip_id: str, verdict: str = "ORIGIN_CONFIRMED") -> dict:
        return self._post(
            f"/v1/content/{urllib.parse.quote(ctid, safe='')}/verify",
            {"verifier_tip_id": verifier_tip_id, "verdict": verdict},
        )

    def dispute(self, ctid: str, disputer_tip_id: str, reason: str,
                evidence_hash: Optional[str] = None) -> dict:
        return self._post(
            f"/v1/content/{urllib.parse.quote(ctid, safe='')}/dispute",
            {"disputer_tip_id": disputer_tip_id, "reason": reason,
             "evidence_hash": evidence_hash},
        )

    @staticmethod
    def build_nginx_snippet(headers: dict) -> str:
        return "\n".join(f'add_header {k} "{v}";' for k, v in headers.items())

    @staticmethod
    def build_apache_snippet(headers: dict) -> str:
        return "\n".join(f'Header set {k} "{v}"' for k, v in headers.items())

    @staticmethod
    def build_caddy_snippet(headers: dict) -> str:
        lines = "\n".join(f'    {k} "{v}"' for k, v in headers.items())
        return f"header {{\n{lines}\n}}"

    @staticmethod
    def build_netlify_snippet(headers: dict) -> str:
        lines = "\n".join(f"    {k} = \"{v}\"" for k, v in headers.items())
        return f"# netlify.toml\n[[headers]]\n  for = \"/*\"\n  [headers.values]\n{lines}"

    @staticmethod
    def build_meta_tags(meta_tags: dict) -> str:
        return "\n".join(
            f'<meta property="{k}" content="{v}" />'
            for k, v in meta_tags.items()
        )


# ══════════════════════════════════════════════════════════════════════════════
# TRUST CLIENT
# ══════════════════════════════════════════════════════════════════════════════

class TIPTrustClient:
    def __init__(self, node_url: str, timeout: int = 10, api_key: Optional[str] = None):
        self._url     = node_url
        self._timeout = timeout
        self._api_key = api_key

    def _get(self, path: str) -> dict:
        return _request(self._url, path, timeout=self._timeout, api_key=self._api_key)

    def _post(self, path: str, body: dict) -> dict:
        return _request(self._url, path, "POST", body, self._timeout, self._api_key)

    def get_score(self, tip_id: str) -> dict:
        return self._get(f"/v1/identity/{urllib.parse.quote(tip_id, safe='')}/score")

    def get_history(self, tip_id: str) -> dict:
        return self._get(f"/v1/identity/{urllib.parse.quote(tip_id, safe='')}/history")

    def compute_tier(self, score: int) -> dict:
        """Compute tier locally from a known score — no network call."""
        tier = get_tier(score)
        return {"name": tier.name, "label": tier.label, "color": tier.color,
                "min": tier.min, "max": tier.max}

    def generate_score_proof(self, score: int, threshold: int, private_key: str) -> dict:
        """
        Generate a ZK proof that score >= threshold without revealing the actual score.
        """
        return compute_zk_score_proof(score, threshold, private_key)

    def verify_score_proof(self, proof: str, commitment: str,
                           threshold: int, claimed_above: bool) -> bool:
        """Verify a ZK score proof."""
        return verify_zk_score_proof(proof, commitment, threshold, claimed_above)

    def get_revocations(self, since: Optional[str] = None) -> dict:
        path = "/v1/revocations"
        if since:
            path += f"?since={urllib.parse.quote(since)}"
        return self._get(path)

    def is_revoked(self, tip_id: str) -> bool:
        try:
            rec = self._get(f"/v1/identity/{urllib.parse.quote(tip_id, safe='')}")
            return rec.get("status") == "revoked"
        except TIPHTTPError:
            return False

    def revoke(
        self,
        tip_id: str,
        tx_type: str,
        issuing_vp_id: str,
        reason_code: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        signature: Optional[str] = None,
    ) -> dict:
        return self._post("/v1/revocations", {
            "tip_id":        tip_id,
            "tx_type":       tx_type,
            "issuing_vp_id": issuing_vp_id,
            "reason_code":   reason_code,
            "evidence_hash": evidence_hash,
            "signature":     signature,
        })

    def check_uniqueness(self, zk_proof: str, hash_commitment: Optional[str] = None) -> dict:
        """Check uniqueness via ZK proof. Returns boolean only — never the hash."""
        return self._post("/v1/dedup/check", {
            "zk_proof":       zk_proof,
            "hash_commitment": hash_commitment or "",
        })

    def get_merkle_root(self) -> dict:
        return self._get("/v1/dedup/merkle-root")


# ══════════════════════════════════════════════════════════════════════════════
# BADGES CLIENT  (pure SVG generation — no network)
# ══════════════════════════════════════════════════════════════════════════════

_SERIF  = "Cormorant Garamond, Georgia, serif"
_ORIGIN_COLORS = {"OH": "#2563A8", "AA": "#7C3AED", "AG": "#C07318", "MX": "#8895A7"}
_ORIGIN_LABELS = {"OH": "Original Human", "AA": "AI-Assisted",
                  "AG": "AI-Generated", "MX": "Mixed / Composite"}

import math


class TIPBadgesClient:
    def __init__(self, node_url: str = "", timeout: int = 10, api_key: Optional[str] = None):
        self._url     = node_url
        self._timeout = timeout
        self._api_key = api_key

    # ── Colour helpers ────────────────────────────────────────────────────────
    @staticmethod
    def tier_color(score: int) -> str:
        if score >= 800: return "#1A8A5C"
        if score >= 600: return "#2563A8"
        if score >= 400: return "#A88B15"
        if score >= 200: return "#C07318"
        return "#C53030"

    @staticmethod
    def tier_label(score: int) -> str:
        if score >= 800: return "Highly Trusted"
        if score >= 600: return "Trusted"
        if score >= 400: return "Review Advised"
        if score >= 200: return "Low Trust"
        return "Not Trusted"

    # ── Arc-text helper ───────────────────────────────────────────────────────
    @staticmethod
    def _arc_letters(cx: float, cy: float, text: str, radius: float,
                     start_deg: float, end_deg: float, font_size: float,
                     fill: str, flip: bool = False, weight: str = "700") -> str:
        chars   = list(text)
        n       = max(len(chars) - 1, 1)
        span    = end_deg - start_deg
        step    = span / n
        parts   = []
        for i, ch in enumerate(chars):
            deg = (end_deg - i * step) if flip else (start_deg + i * step)
            rad = math.radians(deg - 90)
            x   = cx + radius * math.cos(rad)
            y   = cy + radius * math.sin(rad)
            rot = deg + 180 if flip else deg
            parts.append(
                f'<text x="{x:.2f}" y="{y:.2f}" text-anchor="middle" '
                f'dominant-baseline="middle" font-size="{font_size:.2f}" '
                f'fill="{fill}" font-family="{_SERIF}" font-weight="{weight}" '
                f'transform="rotate({rot:.2f},{x:.2f},{y:.2f})">'
                f'{ch}</text>'
            )
        return "".join(parts)

    # ── AI Trust ID™ Seal ─────────────────────────────────────────────────────
    def render_seal(
        self,
        score: int,
        size: int = 200,
        variant: str = "gold-dark",
        founding: bool = False,
    ) -> str:
        """Render the AI Trust ID™ Seal as a standalone SVG string."""
        S       = float(size)
        cx = cy = S / 2
        R       = S / 2 - S * 0.028
        tR      = R - S * 0.062
        iR      = R - S * 0.135
        tc      = self.tier_color(score)

        is_gold  = variant == "gold-dark"
        is_light = variant == "light"
        uid      = f"s{score}{size}{variant[:2]}"

        bg_fill    = f"url(#bg{uid})" if is_gold else ("#FFFFFF" if is_light else "#0A0A0A")
        ring_color = f"url(#rg{uid})" if is_gold else ("#111111" if is_light else "#FFFFFF")
        arc_fill   = f"url(#rg{uid})" if is_gold else ("#111111" if is_light else "#FFFFFF")
        dim_fill   = "#4A6080" if is_gold else ("#666666" if is_light else "#888888")

        # Shield geometry
        sW = S * 0.19; sH = S * 0.24
        sX = cx - sW / 2; sY = cy - S * 0.30
        sCY = sY + sH * 0.52
        shield_d = (
            f"M{cx} {sY} L{sX} {sY+sH*.28} V{sY+sH*.62} "
            f"C{sX} {sY+sH*.9} {cx-sW*.02} {sY+sH*.99} {cx} {sY+sH} "
            f"C{cx+sW*.02} {sY+sH*.99} {sX+sW} {sY+sH*.9} {sX+sW} {sY+sH*.62} "
            f"V{sY+sH*.28}Z"
        )

        # Shield icon
        ck = {
            "x1": cx-sW*.26, "y1": sCY+sH*.06,
            "x2": cx-sW*.02, "y2": sCY+sH*.22,
            "x3": cx+sW*.28, "y3": sCY-sH*.10
        }
        xo = sW * 0.22; yo = sH * 0.24
        if score >= 600:
            icon = (
                f'<polyline points="{ck["x1"]:.2f},{ck["y1"]:.2f} '
                f'{ck["x2"]:.2f},{ck["y2"]:.2f} {ck["x3"]:.2f},{ck["y3"]:.2f}" '
                f'stroke="{tc}" stroke-width="{S*.024:.2f}" stroke-linecap="round" '
                f'stroke-linejoin="round" fill="none"/>'
            )
        elif score >= 400:
            icon = (
                f'<text x="{cx}" y="{sCY+sH*.08:.2f}" text-anchor="middle" '
                f'dominant-baseline="middle" fill="{tc}" font-size="{S*.13:.2f}" '
                f'font-family="Georgia" font-weight="bold">!</text>'
            )
        else:
            icon = (
                f'<line x1="{cx-xo:.2f}" y1="{sCY-yo:.2f}" '
                f'x2="{cx+xo:.2f}" y2="{sCY+yo:.2f}" '
                f'stroke="{tc}" stroke-width="{S*.022:.2f}" stroke-linecap="round"/>'
                f'<line x1="{cx+xo:.2f}" y1="{sCY-yo:.2f}" '
                f'x2="{cx-xo:.2f}" y2="{sCY+yo:.2f}" '
                f'stroke="{tc}" stroke-width="{S*.022:.2f}" stroke-linecap="round"/>'
            )

        # Separator dots
        dots = ""
        for deg in (-148, 148):
            rad = math.radians(deg - 90)
            dx  = cx + tR * math.cos(rad)
            dy  = cy + tR * math.sin(rad)
            dots += f'<circle cx="{dx:.2f}" cy="{dy:.2f}" r="{S*.007:.2f}" fill="{ring_color}" opacity="0.35"/>'

        # Founding star
        founding_star = ""
        if founding:
            sx = cx + iR * 0.62; sy = cy - iR * 0.62
            founding_star = (
                f'<circle cx="{sx:.2f}" cy="{sy:.2f}" r="{S*.072:.2f}" '
                f'fill="{bg_fill}" stroke="{ring_color}" stroke-width="{S*.009:.2f}"/>'
                f'<text x="{sx:.2f}" y="{sy:.2f}" text-anchor="middle" '
                f'dominant-baseline="middle" fill="{arc_fill}" '
                f'font-size="{S*.068:.2f}" font-family="Georgia">&#9733;</text>'
            )

        # Gradients
        gradients = ""
        if is_gold:
            gradients = (
                f'<radialGradient id="rg{uid}" cx="50%" cy="22%" r="78%">'
                f'<stop offset="0%" stop-color="#EDD67A"/>'
                f'<stop offset="52%" stop-color="#C9A84C"/>'
                f'<stop offset="100%" stop-color="#7A5510"/>'
                f'</radialGradient>'
                f'<radialGradient id="bg{uid}" cx="50%" cy="36%" r="64%">'
                f'<stop offset="0%" stop-color="#16243E"/>'
                f'<stop offset="100%" stop-color="#0B1629"/>'
                f'</radialGradient>'
            )

        shadow_flood = "rgba(0,0,0,0.10)" if is_light else "rgba(0,0,0,0.5)"
        top_arc = self._arc_letters(cx, cy, "AI  TRUST  ID™",          tR, -124, -56,  S*0.067, arc_fill, flip=False)
        bot_arc = self._arc_letters(cx, cy, "AI  TRUST  REGISTRY™",    tR,   56, 124,  S*0.040, arc_fill, flip=True)

        return (
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
            f'fill="none" xmlns="http://www.w3.org/2000/svg">\n'
            f'<defs>\n{gradients}'
            f'<filter id="sh{uid}" x="-18%" y="-18%" width="136%" height="136%">'
            f'<feDropShadow dx="0" dy="{S*0.016:.2f}" stdDeviation="{S*0.022:.2f}" '
            f'flood-color="{shadow_flood}"/></filter>\n</defs>\n'
            f'<circle cx="{cx}" cy="{cy}" r="{R:.2f}" fill="{bg_fill}" filter="url(#sh{uid})"/>\n'
            f'<circle cx="{cx}" cy="{cy}" r="{R:.2f}" stroke="{ring_color}" '
            f'stroke-width="{S*0.015:.2f}" fill="none"/>\n'
            f'<circle cx="{cx}" cy="{cy}" r="{iR:.2f}" stroke="{ring_color}" '
            f'stroke-width="{S*0.004:.2f}" fill="none" opacity="0.16"/>\n'
            f'{dots}\n{top_arc}\n{bot_arc}\n'
            f'<path d="{shield_d}" fill="{tc}1C" stroke="{tc}" '
            f'stroke-width="{S*0.014:.2f}" stroke-linejoin="round"/>\n'
            f'{icon}\n'
            f'<text x="{cx}" y="{cy+S*0.155:.2f}" text-anchor="middle" '
            f'fill="{tc}" font-size="{S*0.118:.2f}" '
            f'font-family="{_SERIF}" font-weight="700">{score}</text>\n'
            f'<text x="{cx}" y="{cy+S*0.22:.2f}" text-anchor="middle" '
            f'fill="{dim_fill}" font-size="{S*0.046:.2f}" '
            f'font-family="{_SERIF}" letter-spacing="1">/ 1000</text>\n'
            f'{founding_star}\n'
            f'</svg>'
        )

    # ── TIP™ Powered Mark ─────────────────────────────────────────────────────
    def render_tip_mark(self, size: int = 140, variant: str = "light") -> str:
        """Render the TIP™ Powered Mark (open, Apache 2.0)."""
        S       = float(size)
        cx = cy = S / 2
        R       = S / 2 - S * 0.04
        tR      = R - S * 0.064
        iR      = R - S * 0.13

        is_dark = variant == "dark"
        bg      = "#0A0A0A" if is_dark else "#FFFFFF"
        ring    = "#FFFFFF" if is_dark else "#111111"
        sub     = "#888888" if is_dark else "#555555"
        uid     = f"tm{size}{variant[:1]}"

        dots = ""
        for deg in (-152, 152):
            rad = math.radians(deg - 90)
            dx  = cx + tR * math.cos(rad); dy = cy + tR * math.sin(rad)
            dots += f'<circle cx="{dx:.2f}" cy="{dy:.2f}" r="{S*.006:.2f}" fill="{ring}" opacity="0.3"/>'

        top_arc = self._arc_letters(cx, cy, "TRUST  IDENTITY  PROTOCOL", tR, -140, -40, S*0.043, ring, False, "600")
        bot_arc = self._arc_letters(cx, cy, "OPEN  SPEC  ·  APACHE  2.0", tR,  40, 140, S*0.038, sub,  True,  "500")
        shadow_flood = "rgba(0,0,0,0.5)" if is_dark else "rgba(0,0,0,0.08)"

        return (
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
            f'fill="none" xmlns="http://www.w3.org/2000/svg">\n'
            f'<defs><filter id="tsh{uid}" x="-15%" y="-15%" width="130%" height="130%">'
            f'<feDropShadow dx="0" dy="{S*0.012:.2f}" stdDeviation="{S*0.018:.2f}" '
            f'flood-color="{shadow_flood}"/></filter></defs>\n'
            f'<circle cx="{cx}" cy="{cy}" r="{R:.2f}" fill="{bg}" filter="url(#tsh{uid})"/>\n'
            f'<circle cx="{cx}" cy="{cy}" r="{R:.2f}" stroke="{ring}" '
            f'stroke-width="{S*0.016:.2f}" fill="none"/>\n'
            f'<circle cx="{cx}" cy="{cy}" r="{iR:.2f}" stroke="{ring}" '
            f'stroke-width="{S*0.005:.2f}" fill="none" opacity="0.13"/>\n'
            f'{dots}\n{top_arc}\n{bot_arc}\n'
            f'<text x="{cx}" y="{cy-S*0.048:.2f}" text-anchor="middle" dominant-baseline="middle" '
            f'fill="{ring}" font-size="{S*0.22:.2f}" font-family="{_SERIF}" '
            f'font-weight="700" letter-spacing="-1">TIP</text>\n'
            f'<line x1="{cx-S*0.10:.2f}" y1="{cy+S*0.048:.2f}" '
            f'x2="{cx+S*0.10:.2f}" y2="{cy+S*0.048:.2f}" '
            f'stroke="{ring}" stroke-width="{S*0.003:.2f}" opacity="0.2"/>\n'
            f'<text x="{cx}" y="{cy+S*0.125:.2f}" text-anchor="middle" dominant-baseline="middle" '
            f'fill="{sub}" font-size="{S*0.054:.2f}" font-family="{_SERIF}" '
            f'font-weight="600" letter-spacing="3">POWERED</text>\n'
            f'</svg>'
        )

    # ── Inline Shield ─────────────────────────────────────────────────────────
    def render_shield(self, score: int, size: int = 48, founding: bool = False) -> str:
        color  = self.tier_color(score)
        border = "#B8942E" if founding else color
        sw     = 2.5 if founding else 2
        if score >= 600:
            icon = (
                f'<path d="M16 24L22 30L34 18" stroke="{color}" '
                f'stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
            )
        elif score >= 400:
            icon = f'<text x="24" y="29" text-anchor="middle" fill="{color}" font-size="16" font-weight="bold">!</text>'
        else:
            icon = (
                f'<line x1="17" y1="19" x2="31" y2="33" stroke="{color}" stroke-width="3" stroke-linecap="round"/>'
                f'<line x1="31" y1="19" x2="17" y2="33" stroke="{color}" stroke-width="3" stroke-linecap="round"/>'
            )
        return (
            f'<svg width="{size}" height="{size}" viewBox="0 0 48 48" fill="none" '
            f'xmlns="http://www.w3.org/2000/svg">'
            f'<path d="M24 4L6 12V22C6 33.1 13.84 43.36 24 46C34.16 43.36 42 33.1 42 22V12L24 4Z" '
            f'fill="{color}12" stroke="{border}" stroke-width="{sw}"/>'
            f'{icon}</svg>'
        )

    # ── Origin Badge Pill ─────────────────────────────────────────────────────
    def render_origin_badge(self, origin_code: str, status: str = "VERIFIED") -> str:
        color  = _ORIGIN_COLORS.get(origin_code, "#8895A7")
        label  = _ORIGIN_LABELS.get(origin_code, origin_code)
        sc     = "#C53030" if status == "DISPUTED" else ("#C07318" if status == "PENDING" else color)
        return (
            f'<svg width="160" height="28" viewBox="0 0 160 28" fill="none" '
            f'xmlns="http://www.w3.org/2000/svg">'
            f'<rect width="160" height="28" rx="4" fill="{color}12" '
            f'stroke="{color}" stroke-width="1"/>'
            f'<text x="10" y="14" dominant-baseline="middle" fill="{color}" '
            f'font-size="11" font-family="JetBrains Mono, monospace" '
            f'font-weight="700">{origin_code}</text>'
            f'<line x1="32" y1="6" x2="32" y2="22" stroke="{color}" stroke-width="1" opacity="0.4"/>'
            f'<text x="40" y="14" dominant-baseline="middle" fill="{color}" '
            f'font-size="10" font-family="Libre Franklin, sans-serif" '
            f'font-weight="600">{label}</text>'
            f'<text x="152" y="14" text-anchor="end" dominant-baseline="middle" fill="{sc}" '
            f'font-size="9" font-family="Libre Franklin, sans-serif" '
            f'font-weight="600" letter-spacing="0.5">{status}</text>'
            f'</svg>'
        )

    # ── HTTP Config Generator ─────────────────────────────────────────────────
    def generate_http_config(
        self,
        tip_id: str,
        ctid: str,
        origin_code: str,
        score: int,
        signature: str = "[ML-DSA-65 signature]",
    ) -> dict:
        """Generate ready-to-paste HTTP header configs for major web servers."""
        origin_label = Origin.label(origin_code).lower().replace(" ", "-")
        tier         = get_tier(score)
        headers = {
            HttpHeaders.AUTHOR:      tip_id,
            HttpHeaders.CONTENT:     ctid,
            HttpHeaders.ORIGIN:      origin_label,
            HttpHeaders.TRUST_SCORE: str(score),
            HttpHeaders.TIER:        tier.name,
            HttpHeaders.SIGNATURE:   signature,
        }
        return {
            "headers":    headers,
            "nginx":      TIPContentClient.build_nginx_snippet(headers),
            "apache":     TIPContentClient.build_apache_snippet(headers),
            "caddy":      TIPContentClient.build_caddy_snippet(headers),
            "netlify":    TIPContentClient.build_netlify_snippet(headers),
            "cloudflare": (
                "// Cloudflare Worker\n" +
                "\n".join(f'response.headers.set("{k}", "{v}");'
                          for k, v in headers.items())
            ),
        }

    def generate_meta_tags(
        self,
        tip_id: str,
        ctid: str,
        origin_code: str,
        score: int,
        status: str = "VERIFIED",
    ) -> str:
        origin_label = Origin.label(origin_code).lower().replace(" ", "-")
        tags = {
            "tip:author":  tip_id,
            "tip:content": ctid,
            "tip:origin":  origin_label,
            "tip:score":   str(score),
            "tip:status":  status,
        }
        return TIPContentClient.build_meta_tags(tags)

    def generate_embed_widget(
        self,
        tip_id: str,
        score: int,
        variant: str = "gold-dark",
        founding: bool = False,
        size: int = 80,
    ) -> str:
        """Generate a self-contained embeddable HTML badge widget."""
        svg   = self.render_seal(score, size, variant, founding)
        tier  = get_tier(score)
        url   = f"https://theailab.org/verify/{urllib.parse.quote(tip_id)}"
        return (
            f'<!-- TIP™ AI Trust ID Badge — theailab.org/trust-identity-protocol -->\n'
            f'<div class="tip-badge" data-tip-id="{tip_id}" '
            f'style="display:inline-block;text-align:center;font-family:sans-serif;">\n'
            f'  <a href="{url}" target="_blank" rel="noopener noreferrer" '
            f'title="Verify this AI Trust ID™" style="display:block;text-decoration:none;">\n'
            f'    {svg}\n'
            f'    <div style="margin-top:6px;font-size:11px;color:#4A5568;">'
            f'{tier.label}</div>\n'
            f'  </a>\n'
            f'</div>\n'
            f'<!-- End TIP™ Badge -->'
        )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN TIPClient
# ══════════════════════════════════════════════════════════════════════════════

class TIPClient:
    """
    TIP Protocol Python SDK — main entry point.

    Example:
        tip = TIPClient(node_url="http://localhost:4000")
        health = tip.ping()
        identity = tip.identity.register(vp_id="...", zk_dedup_proof="zkp:...")
        content  = tip.content.register(author_tip_id="...", origin_code="OH", content="...")
        score    = tip.trust.get_score("tip://id/US-...")
        svg      = tip.badges.render_seal(score=score["score"])
    """

    def __init__(
        self,
        node_url: str,
        api_key: Optional[str] = None,
        timeout: int = 10,
        debug: bool = False,
    ) -> None:
        if not node_url:
            raise ValueError("node_url is required")

        self._url     = node_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._debug   = debug

        self.identity = TIPIdentityClient(self._url, timeout, api_key)
        self.content  = TIPContentClient(self._url, timeout, api_key)
        self.trust    = TIPTrustClient(self._url, timeout, api_key)
        self.badges   = TIPBadgesClient(self._url, timeout, api_key)

    def ping(self) -> dict:
        return _request(self._url, "/health", timeout=self._timeout, api_key=self._api_key)

    def node_info(self) -> dict:
        return _request(self._url, "/v1/node/info", timeout=self._timeout, api_key=self._api_key)

    def peers(self) -> dict:
        return _request(self._url, "/v1/node/peers", timeout=self._timeout, api_key=self._api_key)

    def get_tx(self, tx_id: str) -> dict:
        return _request(
            self._url,
            f"/v1/dag/tx/{urllib.parse.quote(tx_id, safe='')}",
            timeout=self._timeout, api_key=self._api_key,
        )

    def register_vp(self, name: str, public_key: str,
                    jurisdiction_tier: str = "green") -> dict:
        return _request(self._url, "/v1/vp/register", "POST", {
            "name":              name,
            "public_key":        public_key,
            "jurisdiction_tier": jurisdiction_tier,
        }, self._timeout, self._api_key)

    def resolve_vp(self, vp_id: str) -> dict:
        return _request(
            self._url,
            f"/v1/vp/{urllib.parse.quote(vp_id, safe='')}",
            timeout=self._timeout, api_key=self._api_key,
        )
