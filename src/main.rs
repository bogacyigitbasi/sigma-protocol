use std::io::Read;

// create a collusion resistant hash from concat
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
// we will need random variables and added rand to dependencies
use rand::Rng;
// needed to use new hash
use sha2::Digest;
use sha2::Sha256;

// Lets recap the scenario prover knows a value is where g^x = y mod p
// 1) Prover picks a random value r, calculates value commitment r = g^k mod p
// 2) Prover simulates the verifier, picks another random value c and calculate response
// 3) Prover calculates the response z = r + x*c mod p and sends it to verifier
// 4) Verifier will compare if g^z = y^c*z (he will calculate the c using the same hash function with the r value and the function y)

fn modular_exp(g: u64, x: u64, p: u64) -> u64 {
    let mut result = 1;
    let mut g = g % p;
    let mut x = x;

    while x > 0 {
        // if x is odd, multiply result
        if x % 2 == 1 {
            result = result * g;
        }
        // x = x/2
        x = x >> 1;
        // g to g^2
        g = g * g % p;
    }
    result % p
}

// we are using sha256 and coverting the numbers to bytes first
// concatenate them. calculate hash and convert it to BigInt and then u64
fn create_challenge(a: u64, y: u64, p: u64) -> u64 {
    // where a = commitment mod p and y is the g^x mod p
    let mut hash = Sha256::new();
    hash.update(a.to_be_bytes());
    hash.update(y.to_be_bytes());
    let hash = hash.finalize();
    // convert hash to bigint and apply modulo
    let hash_ = BigUint::from_bytes_be(&hash);
    (hash_ % p).to_u64().unwrap() // convert to u64 so we can opearate
}
// main function
fn main() {
    // random number generator
    let mut rng = rand::thread_rng();
    // global param generator g (base)
    const g: u64 = 5;
    // prime modular value to work in finite field
    const p: u64 = 101;
    // witness value -- we want to keep this secret where g^x = y mod p
    let x = 9;
    // calculate y
    let y = modular_exp(g, x, p);

    // now lets prove that we know the value 9 without sharing it with verifier
    // 1 commitment => r = g^k mod p
    // picked random from 1 to p and sent it to modular exponential function to calculate the commitment
    let r = rng.gen_range(1..p);
    let a = modular_exp(g, r, p);
    println!("Prover's commitment : r = {}", a);
    // 2 generate a challenge to use it to generate the response.
    // assume this is done at verifier side
    let c: u64 = create_challenge(a, y, p);
    println!("Verifier's challenge : c = {}", c);
    // 3 calculate the response z = r + x*c mod p -1
    let z = (r + c * x) % (p - 1);
    println!("Prover's response: z = {}", z);

    // final step verifier cchecks g^z mod p == a * y^z mod p
    if (modular_exp(g, z, p) == (a * modular_exp(y, c, p)) % p) {
        println!("Prover's response z {} is valid!", z);
    } else {
        println!("Prover's response z {} is invalid!", z);
    }
}
