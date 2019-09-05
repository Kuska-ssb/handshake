extern crate rand;
extern crate ed25519_dalek;

// use rand::Rng;
use rand::rngs::OsRng;
// use rand_core::CryptoRng;
use ed25519_dalek::Keypair;
// use ed25519_dalek::Signature;

fn main() {
    let mut csprng = OsRng::new().unwrap();
    let keypair = Keypair::generate(&mut csprng);
    println!("Hello world");
}
