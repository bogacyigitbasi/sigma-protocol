// we will use RistrettoPoint to simplify implementation and prevent cofactor issue.
// which explained quite well here: https://crypto.stackexchange.com/a/56345
use curve25519_dalek::ristretto::RistrettoPoint; // a point on Ristretto group to prevent cofactor issue
use curve25519_dalek::scalar::Scalar; // witness, commitment, or challenge will be a scalar value. also the private key
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar}; // base or generator g
use rand::{rngs::OsRng, Rng}; // random
use sha2::{Digest, Sha256};

// Prover
// creates a pubkey
struct Prover {
    privKey: Scalar,
    pubKey: RistrettoPoint, // remember key generation on ECC => pubkey is n.G where n is the private key
}

impl Prover {
    //constructor of Prover
    fn new(&mut self, privKey: Scalar) -> Self {
        let pubKey = &self.privKey * &RISTRETTO_BASEPOINT_POINT; // G is selected as RISTRETTO_BASEPOINT_POINT
        Prover {
            privKey: privKey,
            pubKey: pubKey,
        }
    }

    // similar to previous example
    // prover generates the commitment
    // by selecting a random number r and computing G*r isntead of g^r mod p
    fn commit(&self, rng: &mut OsRng) -> (RistrettoPoint, Scalar) {
        let r = rng.gen();
        let commitment = RISTRETTO_BASEPOINT_POINT * r;
        (commitment, r)
    }

    // compute response using the commitment, challenge and witness (privKey)
    // resp = r + x*C
    fn proof(&self, challenge: Scalar, r: Scalar) -> Scalar {
        r + &self.privKey * challenge
    }
}

struct Verifier {
    challenge: Scalar,
}

impl Verifier {
    fn generate_challenge(&mut self, rng: &mut OsRng) -> Scalar {
        let r = rng.gen();
        self.challenge = r;
        self.challenge
    }
    // g^z == a * y^z
    fn verify(&self, commitment: RistrettoPoint, pubKey: RistrettoPoint, proof: Scalar) -> bool {
        RISTRETTO_BASEPOINT_POINT * proof == commitment + (self.challenge * pubKey)
    }
}
fn main() {}
