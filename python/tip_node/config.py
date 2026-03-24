"""node/config.py — TIP Protocol node configuration."""
from __future__ import annotations
import os, pathlib, hashlib, socket

# Author:    Dinesh Mendhe <chairman@theailab.org>
def load_config() -> dict:
    _hostname = socket.gethostname()
    _default_id = hashlib.sha256((_hostname + "tip-node-v2").encode()).hexdigest()[:16]
    data_dir = os.environ.get("TIP_DATA_DIR", str(pathlib.Path.cwd() / "data"))
    return {
        "node_id":       os.environ.get("TIP_NODE_ID",       _default_id),
        "node_type":     os.environ.get("TIP_NODE_TYPE",      "full"),
        "node_version":  "2.0.0",
        "region":        os.environ.get("TIP_REGION",         "US"),
        "vp_id":         os.environ.get("TIP_VP_ID",          None),
        "host":          os.environ.get("HOST",               "0.0.0.0"),
        "port":          int(os.environ.get("PORT",           "4000")),
        "public_url":    os.environ.get("TIP_PUBLIC_URL",     "http://localhost:4000"),
        "peers":         _parse_list(os.environ.get("TIP_PEERS", "")),
        "data_dir":      data_dir,
        "db_path":       os.environ.get("TIP_DB_PATH", str(pathlib.Path(data_dir) / "tip.db")),
        "genesis_dir":   os.environ.get("TIP_GENESIS_DIR", str(pathlib.Path(data_dir) / "genesis")),
        "node_private_key": os.environ.get("TIP_NODE_PRIVATE_KEY",  None),
        "node_public_key":  os.environ.get("TIP_NODE_PUBLIC_KEY",   None),
        "cors_origins":  _parse_list(os.environ.get("TIP_CORS_ORIGINS", "*")),
        "rate_limit_window": 60,
        "rate_limit_max":    200,
        "initial_score":            500,
        "initial_score_attested":   550,
        "max_score":                1000,
        "juror_min_score":          700,
        "merkle_publish_interval":  6 * 3600,
        "score_recompute_interval": 12 * 3600,
        "prescan_enabled":          True,
        "prescan_default_threshold": 0.85,
        "log_level":     os.environ.get("TIP_LOG_LEVEL", "info"),
    }

def _parse_list(val: str) -> list[str]:
    if not val:
        return []
    return [v.strip() for v in val.split(",") if v.strip()]
