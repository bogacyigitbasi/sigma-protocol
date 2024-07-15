// we will need random variables and added rand to dependencies
use rand::Rng;

// Lets recap the scenario prover knows a value is where g^x = y mod p

// 1) Prover picks a random value k, calculates value commitment r = g^k mod p and sends it to verifier
// 2) Verifier picks another random value v, calculates challenge c = g^v mod p
// 3) Prover calculates the response z = r + x*c mod p and sends it to verifier
// 4) Verifier will compare if g^z = y^c*z

fn modular_g(g: u64, x: u64, p: u64) -> u64 {
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
        g = g * g;
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
    const p: u64 = 2003;
    // witness value -- we want to keep this secret where g^x = y mod p
    let x = 9;
    // calculate y
    let y = modular_g(g, x, p);

    // now lets prove that we know the value 9 without using it ever again.
    // 1 commitment => r = g^k mod p
    // picked random from 1 to p and sent it to modular exponential function to calculate the commitment
    let r = modular_g(g, rng.gen_range(1..p - 1), p);

    //
}
