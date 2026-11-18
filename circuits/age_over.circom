pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * AgeOver: prove you are old enough without revealing your birth date.
 *
 * Cast
 *   Alice      the prover. Wants to get in, and must prove she is at least
 *              minAgeYears old.
 *   Bouncer    the verifier. The server running zk-tower; checks Alice's
 *              proof and lets her in or not.
 *   ID Office  the issuer. Signed Alice's birth date once, like stamping an
 *              ID card. Its public key is known to everyone; its private key
 *              never leaves it.
 *
 * Goal
 *   Alice convinces the Bouncer that:
 *     "I hold a birth date that the ID Office signed, and by that date
 *      I am at least minAgeYears old today."
 *   The Bouncer learns only yes or no. It never sees the birth date or
 *   the signature.
 *
 * What each side knows
 *   public  (Bouncer):  ID Office's public key, today's date
 *   private (Alice):    birth date, ID Office's signature on it
 *
 * Checks (added block by block)
 *   1. message  = Poseidon(birthDate), the value the ID Office signed
 *   2. the ID Office's signature on that message is valid
 *   3. birthDate + minAgeYears years <= currentDate
 *
 * Dates are yyyymmdd numbers, e.g. 15 June 2005 = 20050615.
 */
template AgeOver(minAgeYears) {
    // public: the Bouncer knows these
    signal input issuerAx;      // ID Office's public key (x)
    signal input issuerAy;      // ID Office's public key (y)
    signal input currentDate;   // today, yyyymmdd, chosen by the Bouncer

    // private: only Alice knows these
    signal input birthDate;     // yyyymmdd
    signal input sigR8x;        // ID Office's signature on the birth date (3 parts)
    signal input sigR8y;
    signal input sigS;

    // 1. message = Poseidon(birthDate), the value the ID Office signed
    component msg = Poseidon(1);
    msg.inputs[0] <== birthDate;

    // 2. check the ID Office's signature
    // Bouncer knows the ID Office's public key. Alice privately holds the signature. 
    // This block proves that "the ID Office really signed this birth date"
    component issuerSigVerifier = EdDSAPoseidonVerifier();
    issuerSigVerifier.enabled <== 1;
    issuerSigVerifier.Ax <== issuerAx;
    issuerSigVerifier.Ay <== issuerAy;

    issuerSigVerifier.S <== sigS;
    issuerSigVerifier.R8x <== sigR8x;
    issuerSigVerifier.R8y <== sigR8y;

    issuerSigVerifier.M <== msg.out;

    // 3. Alice is at least minAgeYears old: birthDate + minAgeYears*10000 <= currentDate
    // Range-check birthDate and currentDate to avoid overflow security attacks
    component birthDateBits = Num2Bits(27);
    birthDateBits.in <== birthDate;

    component currentDateBits = Num2Bits(27);
    currentDateBits.in <== currentDate;

    component ageCheck = LessEqThan(28);
    ageCheck.in[0] <== birthDate + minAgeYears * 10000;
    ageCheck.in[1] <== currentDate;
    ageCheck.out === 1;
}

// Alice must be at least 18
component main { public [issuerAx, issuerAy, currentDate] } = AgeOver(18);
