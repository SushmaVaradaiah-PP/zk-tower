/*
Trusted setup for age_over.circom (Groth16).

Turns the compiled circuit into:
- proving key       compiled/age_over_final.zkey                (Alice uses it to make proofs)
- verification key  compiled/age_over_verification_key.json     (Bouncer uses it to check the proof)
*/
const crypto = require("crypto");
const fs = require("fs");
const snarkjs = require("snarkjs");

// Setup phase 1: from the public Perpetual Powers of Tau ceremony (PSE).
// 2^13 = 8,192 constraints is enough for our ~4,500.
const PTAU = "ppot_0080_13.ptau";
const PTAU_URL = `https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/${PTAU}`;

const R1CS = "compiled/age_over.r1cs";
const ZKEY_0 = "compiled/age_over_0000.zkey";
const ZKEY_1 = "compiled/age_over_0001.zkey";
const ZKEY_2 = "compiled/age_over_0002.zkey";
const ZKEY_FINAL = "compiled/age_over_final.zkey";
const VKEY = "compiled/age_over_verification_key.json";

const logger = { info: console.log, warn: console.warn, error: console.error, debug: () => { } };

function step(name) {
    console.log(`\n*** ${name} ***`);
}

async function main() {
    if (!fs.existsSync(R1CS)) throw new Error(`${R1CS} not found, run: yarn compile:age-over`);

    step("step0: get setup phase 1 (ptau)");
    if (fs.existsSync(PTAU)) {
        console.log(`${PTAU} already downloaded`);
    } else {
        const res = await fetch(PTAU_URL);
        if (!res.ok) throw new Error(`download failed: ${res.status} ${PTAU_URL}`);
        fs.writeFileSync(PTAU, Buffer.from(await res.arrayBuffer()));
        console.log(`downloaded ${PTAU}`);
    }

    step("step1: circuit info");
    await snarkjs.r1cs.info(R1CS, logger);

    step("step2: setup phase 2, start (circuit-specific)");
    await snarkjs.zKey.newZKey(R1CS, PTAU, ZKEY_0, logger);

    // Each contribution mixes in secret randomness. The setup is safe as long
    // as at least one contributor throws theirs away.
    step("step3: setup phase 2, contribution 1");
    await snarkjs.zKey.contribute(ZKEY_0, ZKEY_1, "1st contributor", crypto.randomBytes(32).toString("hex"), logger);

    step("step4: setup phase 2, contribution 2");
    await snarkjs.zKey.contribute(ZKEY_1, ZKEY_2, "2nd contributor", crypto.randomBytes(32).toString("hex"), logger);

    // A public random beacon finishes the setup, so no contributor gets the last word.
    step("step5: random beacon");
    const beaconHash = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    await snarkjs.zKey.beacon(ZKEY_2, ZKEY_FINAL, "final beacon", beaconHash, 10, logger);

    step("step6: verify the final proving key");
    const ok = await snarkjs.zKey.verifyFromR1cs(R1CS, PTAU, ZKEY_FINAL, logger);
    if (!ok) throw new Error("final zkey does not match the circuit and ptau");

    step("step7: export the verification key");
    const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_FINAL, logger);
    fs.writeFileSync(VKEY, JSON.stringify(vkey, null, 2) + "\n");
    console.log(`written ${ZKEY_FINAL} and ${VKEY}`);
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error(err.message);
        process.exit(1);
    });
