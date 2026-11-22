"""Local synthetic assurance helpers; not a healthcare deployment.

Run verification needs the independently retained final checkpoint of a fresh
gateway log. A site can still hide a suffix by supplying an older checkpoint;
there is no external anchor or signed run identifier here.

EncryptedRecordStore demonstrates key deletion, not physical memory erasure,
backup destruction, or a KMS. Its plaintext commitments remain in the log.
License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
from __future__ import annotations

import secrets
from collections.abc import MutableMapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import tip_agentic as ta


def verify_run(receipts: list[dict], final_checkpoint: dict,
               directory: ta.IdentityDirectory) -> ta.Verdict:
    """Verify the full ordered log against a known final signed checkpoint.

This checks receipt integrity/completeness, not action authority: use
verify_evidence on individual request bundles for that separate question.
"""
    try:
        cb = final_checkpoint["body"]
        key = directory.key_for(cb["site"])
        if key is None:
            return ta.Verdict(ta.INDETERMINATE, ["unknown checkpoint site"])
        if (cb.get("schema") != ta.SCHEMA or cb.get("type") != "checkpoint"
                or cb.get("site_key") != key
                or not ta.verify_body(cb, final_checkpoint["sig"], key)):
            return ta.Verdict(ta.INVALID, ["invalid final checkpoint"])
        if type(cb.get("size")) is not int or cb["size"] < 0 or len(receipts) != cb["size"]:
            return ta.Verdict(ta.INVALID, ["run size differs from final checkpoint"])
        ids = []
        for index, receipt in enumerate(receipts):
            rb = receipt["body"]
            if (rb.get("schema") != ta.SCHEMA or rb.get("type") != "receipt"
                    or rb.get("site") != cb["site"] or rb.get("site_key") != key
                    or type(rb.get("log_index")) is not int or rb["log_index"] != index
                    or not ta.verify_body(rb, receipt["sig"], key)):
                return ta.Verdict(ta.INVALID, ["receipt signature, site or sequence invalid"])
            ids.append(ta.record_id(receipt))
        if len(set(ids)) != len(ids) or ta.merkle_root(ids) != cb["root"]:
            return ta.Verdict(ta.INVALID, ["run differs from checkpointed log"])
        return ta.Verdict(ta.VALID)
    except (KeyError, TypeError, ValueError, AttributeError):
        return ta.Verdict(ta.INVALID, ["malformed run evidence"])


class EncryptedRecordStore(MutableMapping):
    """AES-256-GCM per-record keys, with resource name authenticated as AAD.

Deleting a mapping entry removes its only key from this store and retains its
ciphertext for the demonstration. Python cannot guarantee zeroisation of old
key/plaintext objects. Callers, backups or a compromised process may hold copies.
Only the mapping API models deletion; a production design needs a separate KMS.
"""

    def __init__(self):
        self._keys: dict[str, bytes] = {}
        self._ciphertexts: dict[str, bytes] = {}

    def __getitem__(self, resource: str) -> bytes:
        key = self._keys[resource]  # a deleted key fails closed
        blob = self._ciphertexts[resource]
        return AESGCM(key).decrypt(blob[:12], blob[12:], resource.encode("utf-8"))

    def __setitem__(self, resource: str, content: bytes) -> None:
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        blob = nonce + AESGCM(key).encrypt(nonce, content, resource.encode("utf-8"))
        self._ciphertexts[resource] = blob
        self._keys[resource] = key

    def __delitem__(self, resource: str) -> None:
        del self._keys[resource]

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    def ciphertext_for(self, resource: str) -> bytes:
        return self._ciphertexts[resource]

    def has_key(self, resource: str) -> bool:
        return resource in self._keys
