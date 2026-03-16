"""Compatibility wrapper: node.genesis → tip_node.genesis"""
from tip_node.genesis import (
    GENESIS_TX_ID,
    GENESIS_TIMESTAMP,
    GENESIS_CHAIN_ID,
    GENESIS_PAYLOAD,
    GENESIS_HASH,
    _compute_genesis_hash,
    get_founding_vp,
    get_initial_params,
    validate_genesis_block,
    build_genesis_block,
)
__all__ = [
    "GENESIS_TX_ID", "GENESIS_TIMESTAMP", "GENESIS_CHAIN_ID",
    "GENESIS_PAYLOAD", "GENESIS_HASH", "_compute_genesis_hash",
    "get_founding_vp", "get_initial_params",
    "validate_genesis_block", "build_genesis_block",
]
