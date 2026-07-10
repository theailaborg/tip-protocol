/**
 * exercise-tx-types.mjs — drive every API-reachable tx type against the live
 * local cluster and report which types landed on chain.
 *
 * Uses genesis-data/backups key material: founding VP (registrations,
 * revocation), founding identities (consents, verify, dispute, jury), node
 * keys (endpoint announce). Registers a throwaway identity for the flows
 * that mutate or destroy their subject (key rotation, retract, revocation).
 *
 * Time-gated types this cannot reach in one run: ADJUDICATION_RESULT /
 * APPEAL_* (72h commit window), PRESCAN_REVIEW_* (48h grace + reviewer
 * assignment), COMMITTEE_ROTATION (round-gated, happens on its own).
 *
 *   node scripts/exercise-tx-types.mjs
 */
import { createRequire } from 'module';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const ROOT = path.resolve(__dirname, '..');
const SHARED = path.join(ROOT, 'shared');

const { initCrypto, shake256, tipNormalize, signBody, generateMLDSAKeypair } = require(path.join(SHARED, 'crypto'));
const PC = require(path.join(SHARED, 'protocol-constants'));
const { nowMs } = require(path.join(SHARED, 'time'));
const { getGenesisPayload } = require(path.join(ROOT, 'node/src/genesis'));
const contentRegisterSchema = require(path.join(ROOT, 'node/src/schemas/content-register'));
const registerIdentitySchema = require(path.join(ROOT, 'node/src/schemas/register-identity'));
const updateProfileSchema = require(path.join(ROOT, 'node/src/schemas/update-profile'));
const keyRotatedSchema = require(path.join(ROOT, 'node/src/schemas/key-rotated'));
const linkPlatformSchema = require(path.join(ROOT, 'node/src/schemas/link-platform'));

const N1 = 'http://localhost:4000';
const N2 = 'http://localhost:4100';

await initCrypto();
try { PC._resetForTesting(); } catch { /* not yet init */ }
PC.init(getGenesisPayload().protocol_constants);

const backupDir = path.join(ROOT, 'genesis-data', 'backups');
const idBackups = fs.readdirSync(backupDir).filter(n => n.startsWith('tip-id-')).map(n => JSON.parse(fs.readFileSync(path.join(backupDir, n), 'utf8')));
const vpBackup = JSON.parse(fs.readFileSync(path.join(backupDir, fs.readdirSync(backupDir).find(n => n.startsWith('tip-vp-'))), 'utf8'));
const nodeBackups = fs.readdirSync(backupDir).filter(n => n.startsWith('tip-node-')).map(n => JSON.parse(fs.readFileSync(path.join(backupDir, n), 'utf8')));

const results = [];
function log(phase, ok, detail) {
  results.push({ phase, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${phase}  ${detail || ''}`);
}

async function post(url, body) {
  const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  const text = await resp.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: resp.status, json };
}

function psql(q) {
  return execSync(`docker exec shared-postgres psql -U root -d tip_node1 -tAc "${q.replace(/"/g, '\\"')}"`).toString().trim();
}

async function waitFor(desc, checkFn, timeoutMs = 30000) {
  const start = nowMs();
  while (nowMs() - start < timeoutMs) {
    if (await checkFn()) return true;
    await new Promise(r => setTimeout(r, 1500));
  }
  console.log(`  (timeout waiting: ${desc})`);
  return false;
}

function contentBody(signer, text) {
  const body = {
    signer_tip_id: signer.tip_id, origin_code: 'OH', content: text,
    media_canonical_hash: null, content_type_hint: null, cna_version: '2.2',
    attribution_mode: 'self',
    authors: [{ tip_id: signer.tip_id, tip_id_type: signer.tip_id_type || 'personal', contribution_role: 'creator' }],
    extras: {}, registered_urls: [`https://example.com/x/${nowMs()}-${Math.random().toString(36).slice(2, 8)}`],
  };
  const canonical = contentRegisterSchema.buildSigningPayload(body, shake256(tipNormalize(text)));
  body.signature = contentRegisterSchema.sign(canonical, signer.private_key);
  return body;
}

const before = Object.fromEntries(psql("SELECT tx_type||'|'||count(*) FROM transactions GROUP BY tx_type").split('\n').filter(Boolean).map(l => l.split('|')));

// ── A. UPDATE_PROFILE: founding identities opt into jury + review duty ──────
for (const id of idBackups) {
  try {
    const payload = updateProfileSchema.buildSigningPayload({ tip_id: id.tip_id, juror_consent: true, reviewer_consent: true });
    const signature = updateProfileSchema.sign(payload, id.private_key);
    const r = await post(`${N1}/v1/identity/${encodeURIComponent(id.tip_id)}/profile`, { juror_consent: true, reviewer_consent: true, signature });
    log('UPDATE_PROFILE', r.status === 202, `${id.tip_id.slice(-8)} status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
  } catch (e) { log('UPDATE_PROFILE', false, e.message); }
}

// ── B. REGISTER_IDENTITY: throwaway identity, VP-signed, real ZK proof ──────
let exerciser = null;
try {
  console.log('  (generating dedup proof, can take a minute...)');
  const { generateDedupProof } = require(path.join(SHARED, 'zk'));
  const kp = generateMLDSAKeypair();
  const { dedup_hash, proof } = await generateDedupProof(`GOV-exerciser-${nowMs()}`, '1991-02-03', 'US');
  const fields = {
    region: 'US', public_key: kp.publicKey, dedup_hash, zk_proof: proof,
    verification_tier: 'T1', vp_id: vpBackup.vp_id, social_attested: false,
  };
  const payload = registerIdentitySchema.buildSigningPayload(fields);
  const vp_signature = registerIdentitySchema.sign(payload, vpBackup.private_key);
  const r = await post(`${N1}/v1/identity/register`, { ...fields, vp_signature });
  if (r.status === 202) {
    exerciser = { tip_id: r.json.data.tip_id, tip_id_type: 'personal', private_key: kp.privateKey, public_key: kp.publicKey };
    await waitFor('identity commit', async () => (await fetch(`${N2}/v1/identity/${encodeURIComponent(exerciser.tip_id)}`)).status === 200);
  }
  log('REGISTER_IDENTITY', r.status === 202, `status=${r.status} ${r.json.error || r.json.data?.tip_id || ''}`);
} catch (e) { log('REGISTER_IDENTITY', false, e.message); }

const author = exerciser || idBackups[0];

// ── C. REGISTER_CONTENT x2 by the throwaway ─────────────────────────────────
let c1 = null, c2 = null;
for (const [label, text] of [['c1', `exercise verify+dispute target ${nowMs()}`], ['c2', `exercise update-origin+retract target ${nowMs()}`]]) {
  try {
    const r = await post(`${N1}/v1/content/register`, contentBody(author, text));
    const ctid = r.json.data?.ctid;
    if (label === 'c1') c1 = ctid; else c2 = ctid;
    log('REGISTER_CONTENT', r.status === 202 && !!ctid, `${label}=${ctid} status=${r.status}`);
  } catch (e) { log('REGISTER_CONTENT', false, e.message); }
}
await waitFor('content commit', async () => c2 && (await fetch(`${N2}/v1/content/${encodeURIComponent(c2)}`)).status === 200);

// ── D. CONTENT_VERIFIED (+ paired SCORE_UPDATE): founding id verifies c1 ────
try {
  const verifier = idBackups[1];
  const fields = { verifier_tip_id: verifier.tip_id, ctid: c1, verdict: 'ORIGIN_CONFIRMED' };
  const r = await post(`${N1}/v1/content/${encodeURIComponent(c1)}/verify`, {
    verifier_tip_id: verifier.tip_id, verdict: 'ORIGIN_CONFIRMED', signature: signBody(fields, verifier.private_key),
  });
  log('CONTENT_VERIFIED', r.status === 202, `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
} catch (e) { log('CONTENT_VERIFIED', false, e.message); }

// ── E. UPDATE_ORIGIN: author updates c2 OH -> AA ────────────────────────────
try {
  const fields = { author_tip_id: author.tip_id, ctid: c2, new_origin_code: 'AA' };
  const r = await post(`${N1}/v1/content/${encodeURIComponent(c2)}/update-origin`, { ...fields, signature: signBody(fields, author.private_key) });
  log('UPDATE_ORIGIN', r.status === 202, `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
} catch (e) { log('UPDATE_ORIGIN', false, e.message); }

// ── F. PLATFORM_LINKED / PLATFORM_UNLINKED ─────────────────────────────────
let linkTxId = null;
try {
  const health = await (await fetch(`${N1}/health`)).json();
  const nodeId = health.data?.node_id ?? health.node_id;
  const claimed_at = nowMs();
  const linkFields = { tip_id: author.tip_id, platform: 'github', profile_url: 'https://github.com/tip-exerciser', handle: 'tip-exerciser', claimed_at, node_id: nodeId };
  const payload = linkPlatformSchema.buildSigningPayload(linkFields);
  const claim_signature = linkPlatformSchema.sign(payload, author.private_key);
  const r = await post(`${N1}/v1/identity/${encodeURIComponent(author.tip_id)}/link-platform`, {
    platform: 'github', profile_url: 'https://github.com/tip-exerciser', handle: 'tip-exerciser', claimed_at, claim_signature,
  });
  linkTxId = r.json.data?.tx_id || null;
  log('PLATFORM_LINKED', r.status === 202, `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
} catch (e) { log('PLATFORM_LINKED', false, e.message || JSON.stringify(e.error || e)); }

if (linkTxId) {
  try {
    const unlinkSchema = require(path.join(ROOT, 'node/src/schemas/unlink-platform'));
    const claimed_at = nowMs();
    const fields = { tip_id: author.tip_id, platform: 'github', link_tx_id: linkTxId, claimed_at };
    const payload = unlinkSchema.buildSigningPayload(fields);
    const signature = unlinkSchema.sign(payload, author.private_key);
    const r = await post(`${N1}/v1/identity/${encodeURIComponent(author.tip_id)}/unlink-platform`, { platform: 'github', link_tx_id: linkTxId, claimed_at, signature });
    log('PLATFORM_UNLINKED', r.status === 202, `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
  } catch (e) { log('PLATFORM_UNLINKED', false, e.message); }
}

// ── G0. dispute filing floor check: 550 is genesis-fixed; fresh identities
// start at 500 and no live path credits registrations, so a new cluster
// cannot mint an eligible disputer via APIs (anti-sybil bootstrap by design).
const disputer = idBackups[0].tip_id === author.tip_id ? idBackups[2] : idBackups[0];
{
  const r = await fetch(`${N1}/v1/identity/${encodeURIComponent(disputer.tip_id)}`);
  const score = (await r.json()).data?.score ?? 0;
  if (score < 550) console.log(`  (disputer score ${score} < 550 floor: CONTENT_DISPUTED/JURY_* are bootstrap-gated on a fresh cluster)`);
}

// ── G. CONTENT_DISPUTED + AI_CLASSIFIER_RESULT + JURY_SUMMONS ──────────────
try {
  const evidencePayload = { description: 'exercise dispute: classifier suggests AI generation' };
  const evidence_hash = shake256(require(path.join(SHARED, 'crypto')).canonicalJson ? require(path.join(SHARED, 'crypto')).canonicalJson(evidencePayload) : JSON.stringify(evidencePayload));
  const sigFields = { disputer_tip_id: disputer.tip_id, reason: 'origin_mismatch', ctid: c1, claimed_origin: 'AG', evidence_hash };
  const r = await post(`${N1}/v1/content/${encodeURIComponent(c1)}/dispute`, {
    disputer_tip_id: disputer.tip_id, reason: 'origin_mismatch', claimed_origin: 'AG', evidence_hash,
    signature: signBody(sigFields, disputer.private_key),
    evidence: { payload: evidencePayload, signature: signBody(evidencePayload, disputer.private_key) },
  });
  log('CONTENT_DISPUTED', r.status === 202 || r.json.data?.success, `status=${r.status} ${JSON.stringify(r.json.error) || ''} jurors=${r.json.data?.stage2?.count ?? '?'}`);
} catch (e) { log('CONTENT_DISPUTED', false, e.message); }

// ── H. JURY_VOTE_COMMIT (+ attempt reveal) for summoned jurors we control ──
await waitFor('summons commit', async () => psql(`SELECT count(*) FROM transactions WHERE tx_type='JURY_SUMMONS' AND data::jsonb->>'ctid'='${c1}'`) !== '0');
try {
  const summonRows = psql(`SELECT data::jsonb->>'juror_tip_id' FROM transactions WHERE tx_type='JURY_SUMMONS' AND data::jsonb->>'ctid'='${c1}'`).split('\n').filter(Boolean);
  let committed = 0;
  for (const jurorId of summonRows) {
    const juror = idBackups.find(b => b.tip_id === jurorId);
    if (!juror) continue;
    const salt = `exercise-salt-${jurorId.slice(-6)}`;
    const commitment = shake256(`MATCH:${salt}`);
    const commitFields = { juror_tip_id: jurorId, commitment };
    const r = await post(`${N1}/v1/content/${encodeURIComponent(c1)}/jury/commit`, {
      ...commitFields, signature: signBody({ ...commitFields, ctid: c1, is_appeal: false }, juror.private_key),
    });
    if (r.status === 202) committed++;
    // Reveal attempt: expected to be rejected while the 72h commit window is open
    const revealFields = { juror_tip_id: jurorId, vote: 'MATCH', salt };
    const rv = await post(`${N1}/v1/content/${encodeURIComponent(c1)}/jury/reveal`, {
      ...revealFields, signature: signBody({ ...revealFields, ctid: c1, is_appeal: false }, juror.private_key),
    });
    if (rv.status === 202) console.log('  (reveal accepted early)');
  }
  log('JURY_VOTE_COMMIT', committed > 0, `committed=${committed}/${summonRows.length} summoned`);
} catch (e) { log('JURY_VOTE_COMMIT', false, e.message); }

// ── I. KEY_ROTATED: throwaway rotates to a fresh key ────────────────────────
let rotatedKey = null;
if (exerciser) {
  try {
    const newKp = generateMLDSAKeypair();
    const effective_at = nowMs() + 60_000;
    const old_key_fingerprint = shake256(exerciser.public_key);
    const fields = { tip_id: exerciser.tip_id, algorithm: 'ml-dsa-65', new_public_key: newKp.publicKey, old_key_fingerprint, effective_at };
    const payload = keyRotatedSchema.buildSigningPayload(fields);
    const signature = keyRotatedSchema.sign(payload, exerciser.private_key);
    const r = await post(`${N1}/v1/identity/${encodeURIComponent(exerciser.tip_id)}/keys/rotate`, { ...fields, signature });
    if (r.status === 202) rotatedKey = newKp;
    log('KEY_ROTATED', r.status === 202, `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
  } catch (e) { log('KEY_ROTATED', false, e.message); }
}

// ── J. CONTENT_RETRACTED: author retracts c2 (post-rotation key if rotated) ─
try {
  const key = rotatedKey ? rotatedKey.privateKey : author.private_key;
  const fields = { author_tip_id: author.tip_id, ctid: c2 };
  const r = await post(`${N1}/v1/content/${encodeURIComponent(c2)}/retract`, { ...fields, signature: signBody(fields, key) });
  log('CONTENT_RETRACTED', r.status === 202, `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
} catch (e) { log('CONTENT_RETRACTED', false, e.message); }

// ── K. NODE_ENDPOINT_UPDATED: node1 self-announces its docker-network URL ──
try {
  const r = await post(`${N1}/v1/node/endpoint/announce`, { api_endpoint: 'http://node1:4000' });
  log('NODE_ENDPOINT_UPDATED', r.status === 202 || r.json.data?.confirmation === 'unchanged', `status=${r.status} ${JSON.stringify(r.json.error) || r.json.data?.confirmation || ''}`);
} catch (e) { log('NODE_ENDPOINT_UPDATED', false, e.message); }

// ── L. REVOKED: VP revokes the throwaway ────────────────────────────────────
if (exerciser) {
  try {
    const revokeFields = { tx_type: 'REVOKE_VOLUNTARY', tip_id: exerciser.tip_id, reason_code: 'VOLUNTARY', issuing_vp_id: vpBackup.vp_id };
    const r = await post(`${N1}/v1/revocations`, { ...revokeFields, signature: signBody(revokeFields, vpBackup.private_key) });
    log('REVOKED', [200, 201, 202].includes(r.status), `status=${r.status} ${JSON.stringify(r.json.error) || ''}`);
  } catch (e) { log('REVOKED', false, e.message); }
}

// ── Report ──────────────────────────────────────────────────────────────────
await new Promise(r => setTimeout(r, 8000));
console.log('\n=== tx-type deltas on chain (node1) ===');
const after = Object.fromEntries(psql("SELECT tx_type||'|'||count(*) FROM transactions GROUP BY tx_type").split('\n').filter(Boolean).map(l => l.split('|')));
for (const [type, count] of Object.entries(after).sort()) {
  const delta = count - (before[type] || 0);
  if (delta > 0) console.log(`  ${type}: +${delta} (now ${count})`);
}
console.log('\nmempool:', psql('SELECT count(*) FROM mempool'));
console.log('failures:', results.filter(r => !r.ok).length ? results.filter(r => !r.ok).map(r => r.phase).join(', ') : 'none');
// snarkjs leaves curve worker threads alive; without this the process never exits
process.exit(0);
