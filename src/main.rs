// we will need random variables and added rand to dependencies
use rand::Rng;

// Lets recap the scenario prover knows a value is where g^x = y mod p
// 1) Prover picks a random value r, calculates value commitment com = g^r mod p and sends it to verifier
// 2) Verifier picks another random value c as challenge, send it to prover
// 3) Prover calculates the response resp = r + x*c mod p-1 and sends it to verifier
// 4) Verifier will compare if g^resp mod p == com*y^c mod p

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
    let witness = 9;
    // calculate y
    let y = modular_exp(g, witness, p);

    // now lets prove that we know the value 9 without sharing it with verifier
    // 1 commitment => a = g^r mod p
    // picked random from 1 to p and sent it to modular exponential function to calculate the commitment
    let r = rng.gen_range(1..p);
    let com = modular_exp(g, r, p);
    println!("Prover's commitment : r = {}", com);
    // 2 generate a challenge to use it to generate the response.
    // assume this is done at verifier side
    let challenge: u64 = rng.gen_range(1..p);
    println!("Verifier's challenge : c = {}", challenge);
    // 3 calculate the response z = r + x*c mod p -1
    let resp = (r + challenge * witness) % (p - 1);
    println!("Prover's response: z = {}", resp);

    // final step verifier cchecks g^resp mod p == com * y^c mod p
    if (modular_exp(g, resp, p) == (com * modular_exp(y, challenge, p)) % p) {
        println!("Prover's response z {} is valid!", resp);
    } else {
        println!("Prover's response z {} is invalid!", resp);
    }
}
