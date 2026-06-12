"use strict";

const { generateVPId, verifyBodySignature } = require("../../../shared/crypto");
const { nowMs } = require("../../../shared/time");
const { TX_TYPES } = require("../../../shared/constants");
const { validateTransaction } = require("../validators/tx-validator");
const rules = require("../validators/business-rules");
const { withTxId } = require("./helpers");
const { validate } = require("../middleware/validate");
const { getFoundingVP } = require("../genesis");
const interestRegisteredSchema = require("../schemas/interest-registered");
const nodeEndpointUpdateSchema = require("../schemas/node-endpoint-update");
const { nodeSignedAuto } = require("./helpers");
const { log } = require("../logger");

// Liveness + ownership probe timeout. The endpoint must answer /health
// AND identify as the claiming node inside this window.
const ENDPOINT_PROBE_TIMEOUT_MS = 5000;

function createGovernanceService({ dag, scoring, config, submitTx, fetchImpl }) {
  const _fetch = fetchImpl || globalThis.fetch;

  function registerVP(body) {
    // GH #51 — accept legacy `council_signature` or new top-level
    // `signature`; map onto the same internal field for the rest of
    // the function. Lets new clients opt into the unified wire format.
    // GH #60 — also normalise algorithm (default ml-dsa-65) onto the
    // body so signed bytes + tx.data carry it without needing to
    // splat at every read site.
    const normalisedBody = (body && typeof body === "object")
      ? {
          ...body,
          council_signature: body.council_signature || body.signature,
          algorithm: body.algorithm || "ml-dsa-65",
        }
      : body;
    validate(normalisedBody, { name: { required: true }, public_key: { required: true }, jurisdiction: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, jurisdiction, jurisdiction_tier = "green", public_key, algorithm, council_signature, approving_vp_id } = normalisedBody;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP (${foundingVpId}) can approve new VPs` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    // GH #60: algorithm is in the canonical signed bytes — VP attests
    // the (pubkey, algorithm) pair. Field list sorted alphabetically
    // so signer + verifier agree on canonical order.
    const VP_REGISTER_FIELDS = ["algorithm", "approving_vp_id", "jurisdiction", "jurisdiction_tier", "name", "public_key"];
    if (!verifyBodySignature(normalisedBody, council_signature, approvingVp.public_key, VP_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const vpId = generateVPId(jurisdiction, public_key);
    const vpCheck = rules.canRegisterVp(dag, { vp_id: vpId });
    if (!vpCheck.valid) throw { status: vpCheck.error.status, error: vpCheck.error.message };

    const registeredAt = nowMs();

    const vpTx = withTxId({
      tx_type: TX_TYPES.VP_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: { vp_id: vpId, name, jurisdiction, jurisdiction_tier, public_key, algorithm, approving_vp_id },
      // GH #51 — approving VP's council signature lives at tx.signature.
      signature: council_signature,
    });

    const validation = validateTransaction(vpTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(vpTx);

    return { vp_id: vpId, name, jurisdiction_tier, registered_at: registeredAt, confirmation: "proposed" };
  }

  function resolveVP(vpId) {
    const vp = dag.getVP(vpId);
    if (!vp) throw { status: 404, error: "Verification Provider not found" };
    return vp;
  }

  function registerNode(body) {
    // Same GH #51 alias as registerVP — clients can send `signature`
    // or the legacy `council_signature`. GH #60: also normalise
    // algorithm (default ml-dsa-65) onto the body.
    const normalisedBody = (body && typeof body === "object")
      ? {
          ...body,
          council_signature: body.council_signature || body.signature,
          algorithm: body.algorithm || "ml-dsa-65",
        }
      : body;
    validate(normalisedBody, { public_key: { required: true }, council_signature: { required: true }, approving_vp_id: { required: true } });
    const { name, public_key, algorithm, council_signature, approving_vp_id } = normalisedBody;

    const foundingVpId = getFoundingVP().vp_id;
    if (approving_vp_id !== foundingVpId) throw { status: 403, error: `Only the founding VP can approve nodes` };

    const approvingVp = dag.getVP(approving_vp_id);
    if (!approvingVp) throw { status: 403, error: `Approving VP not found` };
    if (approvingVp.status !== "active") throw { status: 403, error: `Approving VP is not active` };

    // Optional public API base URL — peers redirect reviewers here when
    // requested media bytes live on this node's bucket (per-node storage).
    // Origin-only: scheme + host + optional port, no path/query. The VP
    // attests to it (signed field), so a hijacked node can't silently
    // repoint peers at an attacker URL without a fresh council signature.
    const api_endpoint = normalisedBody.api_endpoint;
    if (api_endpoint !== undefined) {
      if (typeof api_endpoint !== "string" || !/^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/i.test(api_endpoint)) {
        throw { status: 400, error: "api_endpoint must be an origin URL (https://host[:port], no path)" };
      }
    }

    // GH #60: algorithm is in canonical signed bytes; alphabetical sort
    // keeps signer/verifier byte-aligned. api_endpoint is optional —
    // verifyBodySignature skips undefined fields, so legacy clients that
    // don't send it keep verifying.
    const NODE_REGISTER_FIELDS = ["algorithm", "api_endpoint", "approving_vp_id", "name", "public_key"];
    if (!verifyBodySignature(normalisedBody, council_signature, approvingVp.public_key, NODE_REGISTER_FIELDS)) {
      throw { status: 403, error: "Council signature verification failed" };
    }

    const nodeId = require("../../../shared/crypto").generateNodeId(public_key);
    const nodeCheck = rules.canRegisterNode(dag, { node_id: nodeId });
    if (!nodeCheck.valid) throw { status: nodeCheck.error.status, error: nodeCheck.error.message };

    const registeredAt = nowMs();

    const nodeTx = withTxId({
      tx_type: TX_TYPES.NODE_REGISTERED, timestamp: registeredAt, prev: dag.getRecentPrev(),
      data: {
        node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`,
        public_key, algorithm, approving_vp_id,
        ...(api_endpoint ? { api_endpoint } : {}),
      },
      // GH #51 — approving VP's council signature lives at tx.signature.
      signature: council_signature,
    });

    const validation = validateTransaction(nodeTx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(nodeTx);

    log.info(`Node registration proposed: ${nodeId}`);
    return {
      node_id: nodeId, name: name || `node-${nodeId.slice(0, 8)}`,
      api_endpoint: api_endpoint || null,
      registered_at: registeredAt, confirmation: "proposed",
    };
  }

  /**
   * Update THIS node's public api_endpoint on chain. Two gates before
   * the tx is built:
   *
   *   1. Ownership probe — GET {endpoint}/health must answer within the
   *      timeout AND report node_id === our registered id. Catches the
   *      "operator typo'd someone else's URL" class: we never publish
   *      an endpoint that doesn't terminate at this very node. Skipped
   *      when clearing (api_endpoint=null).
   *   2. No-op suppression — when the chain row already carries the
   *      same endpoint, return without emitting a tx.
   *
   * The tx is envelope-signed with our own node key (NODE_ENVELOPE) —
   * data.node_id is both subject and signer, so peers' verification
   * enforces self-update structurally. The probe is API-time only;
   * consensus never does network IO.
   */
  async function updateNodeEndpoint(apiEndpoint) {
    const nodeId = config.nodeRegisteredId;
    if (!nodeId) throw { status: 409, error: "Node is not registered (no nodeRegisteredId) — register before announcing an endpoint" };

    const normalised = apiEndpoint == null ? null : String(apiEndpoint).replace(/\/+$/, "");
    nodeEndpointUpdateSchema.validateRequest({ node_id: nodeId, api_endpoint: normalised });

    const row = dag.getNode(nodeId);
    if (!row) throw { status: 409, error: `Node ${nodeId} not on chain yet; wait for NODE_REGISTERED to commit` };
    if ((row.api_endpoint || null) === normalised) {
      return { node_id: nodeId, api_endpoint: normalised, confirmation: "unchanged" };
    }

    if (normalised !== null) {
      let probe;
      try {
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), ENDPOINT_PROBE_TIMEOUT_MS);
        const res = await _fetch(`${normalised}/health`, { signal: ctl.signal });
        clearTimeout(timer);
        probe = await res.json();
      } catch (err) {
        throw { status: 400, error: `api_endpoint probe failed: ${normalised}/health unreachable (${err?.message || err})` };
      }
      // /health responses go through the API envelope wrapper
      // ({ ok, status, data: { node_id, ... } }), so the node_id lives at
      // probe.data.node_id. Accept a raw top-level node_id too for
      // robustness against non-enveloped health endpoints.
      const probedNodeId = probe?.data?.node_id ?? probe?.node_id;
      if (probedNodeId !== nodeId) {
        throw {
          status: 400,
          error: `api_endpoint ownership check failed: ${normalised} answers as "${probedNodeId}" not "${nodeId}". Refusing to publish a URL that is not this node.`,
        };
      }
    }

    const tx = nodeSignedAuto({
      tx_type: TX_TYPES.NODE_ENDPOINT_UPDATED,
      timestamp: nowMs(),
      prev: dag.getRecentPrev(),
      data: { node_id: nodeId, api_endpoint: normalised },
    }, config);

    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(tx);
    log.info(`Node endpoint update proposed: ${nodeId} → ${normalised ?? "(cleared)"}`);
    return { node_id: nodeId, api_endpoint: normalised, confirmation: "proposed" };
  }

  /**
   * Register a new interest in the curated taxonomy. VP-attested:
   * caller must be a registered + active VP and have signed the
   * canonical payload (alphabetical: approving_vp_id, category, label,
   * slug). Slug uniqueness is enforced at commit time via the unified
   * dedup gate (canCommitteeRotation-style); a 409 here surfaces the
   * duplicate before the tx is even submitted.
   */
  function addInterest(body) {
    interestRegisteredSchema.validateRequest(body, { dag });
    const { slug, label, category, approving_vp_id, signature } = body;
    const canonicalPayload = interestRegisteredSchema.buildSigningPayload({
      slug, label, category, approving_vp_id,
    });
    const approvingVp = dag.getVP(approving_vp_id);
    if (!interestRegisteredSchema.verifySignature(canonicalPayload, signature, approvingVp.public_key)) {
      throw { status: 403, error: "VP signature verification failed" };
    }

    const registeredAt = nowMs();
    const tx = withTxId({
      tx_type:   TX_TYPES.INTEREST_REGISTERED,
      timestamp: registeredAt,
      prev:      dag.getRecentPrev(),
      data:      { slug, label, category, approving_vp_id },
      signature,
    });

    const validation = validateTransaction(tx, dag, {});
    if (!validation.valid) throw { status: 400, error: validation.errors, layer: validation.layer };

    submitTx(tx);
    log.info(`Interest registration proposed: ${slug} (category=${category}, vp=${approving_vp_id})`);
    return { slug, label, category, registered_at: registeredAt, confirmation: "proposed" };
  }

  function listInterests() {
    return { interests: dag.getAllInterests() };
  }

  // Public-route entry: announces the operator-configured endpoint only.
  // No caller-supplied URL ever reaches the chain through this path, so
  // the route stays auth-free — see routes/governance.js.
  async function announceConfiguredEndpoint() {
    if (!config.apiEndpoint) {
      throw { status: 409, error: "TIP_API_ENDPOINT not configured — set it and restart, then announce" };
    }
    return updateNodeEndpoint(config.apiEndpoint);
  }

  return { registerVP, resolveVP, registerNode, updateNodeEndpoint, announceConfiguredEndpoint, addInterest, listInterests };
}

module.exports = { createGovernanceService };
