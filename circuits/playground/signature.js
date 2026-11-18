// Playground: the ID Office signs Alice's birth date, then we verify it.
// Prints the circuit input to the terminal.
//
// Run from circuits/:
//   node playground/signature.js [birthDate] [currentDate]
const crypto = require("crypto");
const { buildEddsa, buildPoseidon } = require("circomlibjs");

const birthDate = process.argv[2] || "20050615"; // 15-June-2005
const currentDate = process.argv[3] || "20261118"; // 18-Nov-2026

async function main() {
    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();
    const F = eddsa.F;

    // 1. ID Office: private key (32 random bytes) and public key A = k · B8
    const prv = crypto.randomBytes(32);
    const pub = eddsa.prv2pub(prv);

    // 2. ID Office: sign Poseidon(birthDate), the same hash as block 1 of the circuit
    const msg = poseidon([BigInt(birthDate)]);
    const sig = eddsa.signPoseidon(prv, msg);
    console.error("sig.R8x           ", F.toObject(sig.R8[0]).toString());
    console.error("sig.R8y           ", F.toObject(sig.R8[1]).toString());
    console.error("sig.S             ", sig.S.toString());

    // 3. Check the signature outside the circuit
    console.error("hash              ", F.toObject(msg).toString());
    console.error("signature valid?  ", eddsa.verifyPoseidon(msg, sig, pub));
    console.error("one day later?    ", eddsa.verifyPoseidon(poseidon([BigInt(birthDate) + 1n]), sig, pub));

    // 4. Alice's credential + the Bouncer's challenge = circuit input
    const input = {
        issuerAx: F.toObject(pub[0]).toString(),
        issuerAy: F.toObject(pub[1]).toString(),
        currentDate: currentDate,
        birthDate: birthDate,
        sigR8x: F.toObject(sig.R8[0]).toString(),
        sigR8y: F.toObject(sig.R8[1]).toString(),
        sigS: sig.S.toString(),
    };
    console.log(JSON.stringify(input, null, 2));
}

main().then(() => process.exit(0));
