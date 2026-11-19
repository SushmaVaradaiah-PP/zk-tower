/*
The ID Office (issuer): creates its keypair once, then signs birthdates.
In real life this is a government ID office and its private key is secret.

In this demo the private keys live inside compiled/
*/

const crypto = require("crypto");
const fs = require("fs");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

const PRIVATE = "compiled/issuer_private.key";
const PUBLIC = "compiled/issuer_public.json";

// Create the ID Office's keypair. Refuses to overwrite an existing key, because that would invalidate every credential already issued.
async function init() {
    if (fs.existsSync(PRIVATE)) throw new Error(`issuer key already exists: ${PRIVATE}`);

    const eddsa = await buildEddsa();
    const F = eddsa.F;

    const prv = crypto.randomBytes(32); // private key: 32 random bytes
    const pub = eddsa.prv2pub(prv);     // public key A = k.B8

    fs.mkdirSync("compiled", { recursive: true });
    fs.writeFileSync(PRIVATE, prv.toString("hex"));
    fs.writeFileSync(PUBLIC, JSON.stringify({
        Ax: F.toObject(pub[0]).toString(),
        Ay: F.toObject(pub[1]).toString()
    }, null, 2) + "\n");
    console.log(`issuer keypair written to ${PRIVATE} / ${PUBLIC}`);
}

// Sign Poseidon(birthDate) and write Alice's credential.
async function issue(birthDate, out) {
    if (!/^[0-9]{8}$/.test(birthDate || "")) throw new Error("birth date must be yyyymmdd");
    if (!out) throw new Error("output file required");

    if (!fs.existsSync(PRIVATE)) throw new Error("no issuer key, run: node scripts/issueCredential.js init");

    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = eddsa.F;

    const prv = Buffer.from(fs.readFileSync(PRIVATE, "utf8").trim(), "hex");
    const pub = eddsa.prv2pub(prv);

    // the same hash as block 1 of the circuit
    const msg = poseidon([BigInt(birthDate)]);
    const sig = eddsa.signPoseidon(prv, msg);
    if (!eddsa.verifyPoseidon(msg, sig, pub)) throw new Error("signature does not verify");

    const credential = {
        issuerAx: F.toObject(pub[0]).toString(),
        issuerAy: F.toObject(pub[1]).toString(),
        birthDate: birthDate,
        sigR8x: F.toObject(sig.R8[0]).toString(),
        sigR8y: F.toObject(sig.R8[1]).toString(),
        sigS: sig.S.toString(),
    };
    fs.writeFileSync(out, JSON.stringify(credential, null, 2) + "\n");
    console.log(`credential for birth date ${birthDate} written to ${out}`);
}

async function main() {
    const [cmd, ...args] = process.argv.slice(2);
    if (cmd === "init") return init();
    if (cmd === "issue") return issue(...args);
    throw new Error("usage: issueCredential.js init | issue <yyyymmdd> <out.json>");
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error(err.message);
        process.exit(1);
    });
