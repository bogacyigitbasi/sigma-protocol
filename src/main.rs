// we will use RistrettoPoint to simplify implementation and prevent cofactor issue.
// which explained quite well here: https://crypto.stackexchange.com/a/56345
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // base or generator g
use curve25519_dalek::ristretto::RistrettoPoint; // a point on Ristretto group to prevent cofactor issue
use curve25519_dalek::scalar::Scalar; // witness, commitment, or challenge will be a scalar value. also the private key
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
    fn new(&self, privKey: Scalar) -> Self {
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
}

fn main() {}
