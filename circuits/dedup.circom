pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

/*
 * DedupHashCircuit
 *
 * Proves knowledge of (gov_id, dob, country) that Poseidon-hash to dedup_hash,
 * without revealing any input.
 *
 * Private inputs (never leave the user's device):
 *   gov_id  — government ID bytes encoded as a BN128 field element
 *   dob     — date of birth as YYYYMMDD integer (e.g. 19900515)
 *   country — ISO-3166-1 country code as integer (charCode[0]*256 + charCode[1])
 *
 * Public output (stored in dedup_registry on the DAG):
 *   dedup_hash — Poseidon(gov_id, dob, country) as a BN128 field element
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 */
template DedupHashCircuit() {
    signal input gov_id;
    signal input dob;
    signal input country;

    signal output dedup_hash;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== gov_id;
    hasher.inputs[1] <== dob;
    hasher.inputs[2] <== country;

    dedup_hash <== hasher.out;
}

component main = DedupHashCircuit();
