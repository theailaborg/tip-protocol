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

from node.config   import load_config
from node.dag      import DAG
from node.scoring  import ScoringEngine
from node.api      import create_server
from node.gossip   import GossipServer
from node.scheduler import start_scheduled_tasks
from node.genesis  import build_genesis_block
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

    # Warn about insecure defaults
    if config["jwt_secret"] == "CHANGE_THIS_IN_PRODUCTION":
        log.warning("TIP_JWT_SECRET is using the default value. Change it before production deployment.")
    if config["admin_api_key"] == "CHANGE_THIS_IN_PRODUCTION":
        log.warning("TIP_ADMIN_API_KEY is using the default value. Change it before production deployment.")

    # 1. Ensure genesis block exists
    try:
        build_genesis_block(config["genesis_dir"])
    except ValueError as exc:
        log.error(str(exc))
        sys.exit(1)

    # 2. Initialise DAG store
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
    server = create_server(dag, scoring, config)
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
