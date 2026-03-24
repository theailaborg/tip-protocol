"""
node/main.py
TIP Protocol Python Node — Production Entry Point

# Author:    Dinesh Mendhe <chairman@theailab.org>
Starts:
  1. DAG store (SQLite or in-memory)
  2. Trust scoring engine
  3. Threaded HTTP REST API server
  4. TCP gossip server (peer DAG propagation)
  5. Scheduled background tasks

Usage:
  python -m node.main
  TIP_PORT=4000 TIP_DATA_DIR=./data python -m node.main

© 2026 The AI Lab Intelligence Unobscured, Inc.
"""
from __future__ import annotations

import os
import pathlib
import signal
import sys

# Allow running as: python -m node.main from the project root
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from shared.crypto import generate_mldsa_keypair
from node.config   import load_config
from node.dag      import DAG
from node.scoring  import ScoringEngine
from node.api      import create_server
from node.gossip   import GossipServer
from node.scheduler import start_scheduled_tasks
from node.logger   import get_logger

log = get_logger("main")


def main() -> None:
    config = load_config()

    log.info("=" * 56)
    log.info("  TIP™ Protocol Node  v2.0.0")
    log.info(f"  Node ID    : {config['node_id']}")
    log.info(f"  Region     : {config['region']}")
    log.info(f"  Port       : {config['port']}")
    log.info(f"  Node type  : {config['node_type']}")
    log.info(f"  DB path    : {config['db_path']}")
    log.info("=" * 56)

    # Load or generate node signing keypair
    if config["node_private_key"] and config["node_public_key"]:
        log.info("Node signing keys loaded from environment")
    else:
        kp = generate_mldsa_keypair()
        config["node_private_key"] = kp["privateKey"]
        config["node_public_key"]  = kp["publicKey"]
        log.warning("No TIP_NODE_PRIVATE_KEY set — generated ephemeral keypair. Tx signatures will not survive restart.")

    # 1. Initialise DAG store (genesis block written from hardcoded constants on first boot)
    # On first boot: if seed.db exists, copy it so founding data is available immediately
    import shutil
    seed_db = pathlib.Path(__file__).parent.parent.parent / "genesis-data" / "seed.db"
    db_path = pathlib.Path(config["db_path"])
    if not db_path.exists() and seed_db.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(seed_db, db_path)
        log.info(f"Copied seed DB to {db_path} (first boot with seeded data)")

    dag = DAG(config)
    log.info(f"DAG initialised. Transactions: {dag.count()}")

    # 3. Scoring engine
    scoring = ScoringEngine(dag, config)
    log.info("Trust scoring engine ready")

    # 4. Gossip server
    gossip = GossipServer(dag, config)
    gossip.start()

    # 5. Scheduled tasks
    start_scheduled_tasks(dag, scoring, gossip, config)

    # 6. HTTP API server (blocking)
    server = create_server(dag, scoring, config, gossip=gossip)
    host   = config["host"]
    port   = config["port"]
    log.info(f"REST API listening on  http://{host}:{port}")
    log.info(f"Health check:          http://{host}:{port}/health")
    log.info(f"Node info:             http://{host}:{port}/v1/node/info")

    def _shutdown(sig, frame):
        log.info("Shutting down gracefully...")
        server.shutdown()
        dag.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Interrupted — shutting down")
    finally:
        gossip.stop()
        dag.close()


if __name__ == "__main__":
    main()
