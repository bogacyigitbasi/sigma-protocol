// we will use RistrettoPoint to simplify implementation and prevent cofactor issue.
// which explained quite well here: https://crypto.stackexchange.com/a/56345

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // base or generator g
use curve25519_dalek::ristretto::RistrettoPoint; // a point on Ristretto group to prevent cofactor issue
use curve25519_dalek::scalar::Scalar; // witness, commitment, or challenge will be a scalar value. also the private key
                                      // use rand_core::OsRng;
use rand::{rngs::OsRng, RngCore}; // random

// Prover
// creates a pubkey
struct Prover {
    privKey: Scalar,
    pubKey: RistrettoPoint, // remember key generation on ECC => pubkey is n.G where n is the private key
}

// created to fix the error of Scalar::random it couldnt find the random
fn generate_random_scalar(rng: &mut OsRng) -> Scalar {
    let mut random_bytes = [0u8; 64]; // 64 byte array u8 random values
    rng.fill_bytes(&mut random_bytes); // fill random vars
    Scalar::from_bytes_mod_order_wide(&random_bytes) // return scalar
}

impl Prover {
    //constructor of Prover
    fn new(privKey: Scalar) -> Self {
        let pubKey = &privKey * &RISTRETTO_BASEPOINT_POINT; // G is selected as RISTRETTO_BASEPOINT_POINT
        Prover {
            privKey: privKey,
            pubKey: pubKey,
        }
    }

    // similar to previous example
    // prover generates the commitment
    // by selecting a random number r and computing G*r isntead of g^r mod p
    fn commit(&self, rng: &mut OsRng) -> (RistrettoPoint, Scalar) {
        let r = generate_random_scalar(rng); // returns scalar
        let commitment = RISTRETTO_BASEPOINT_POINT * r;
        (commitment, r)
    }

    // compute response using the commitment, challenge and witness (privKey)
    // and only public key can verify the privkey
    // resp = r + x*C
    fn proof(&self, challenge: &Scalar, r: &Scalar) -> Scalar {
        r + &self.privKey * challenge
    }
}

struct Verifier {
    challenge: Scalar,
}

impl Verifier {
    fn generate_challenge(&mut self, rng: &mut OsRng) -> Scalar {
        let r = generate_random_scalar(rng); // returns scalar
        self.challenge = r;
        self.challenge
    }
    // public key is G^witness(private key)
    fn verify(
        &self,
        commitment: &RistrettoPoint,
        pub_key: &RistrettoPoint,
        proof: &Scalar,
    ) -> bool {
        RISTRETTO_BASEPOINT_POINT * proof == commitment + (self.challenge * pub_key)
    }
}
extern crate rand_core;

fn main() {
    let mut rng = OsRng; // Secure random number generator from OS

    /// lets define the witness
    let secret = generate_random_scalar(&mut rng);
    // Prover initialization, we generate the private and public keys.
    let prover = Prover::new(secret);
    // compute commitment
    let (commitment, random_scalar) = prover.commit(&mut rng); // Step 1: Prover generates a commitment
                                                               // initialize the Verifier
    let mut verifier = Verifier {
        challenge: Scalar::ZERO,
    };
    // generate a scalar challenge
    let challenge = verifier.generate_challenge(&mut rng); // Step 2: Verifier generates a challenge
                                                           // response/proof generation
    let response = prover.proof(&challenge, &random_scalar); // Step 3: Prover computes the response

    let is_valid = verifier.verify(&commitment, &prover.pubKey, &response); // Step 4: Verifier checks the response

    println!("Verification result: {}", is_valid); // Output the verification result
}
