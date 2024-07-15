// we will need random variables and added rand to dependencies
use rand::Rng;

// Lets recap the scenario prover knows a value is where g^x = y mod p

// 1) Prover picks a random value k, calculates value commitment r = g^k mod p and sends it to verifier
// 2) Verifier picks another random value v, calculates challenge c = g^v mod p
// 3) Prover calculates the response z = r + x*c mod p and sends it to verifier
// 4) Verifier will compare if g^z = y^c*z

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
    let c: u64 = rng.gen_range(1..p);
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
