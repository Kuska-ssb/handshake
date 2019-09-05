extern crate rand;
extern crate ed25519_dalek;
extern crate base64;

// use rand::Rng;
use rand::rngs::OsRng;
// use rand_core::CryptoRng;
use ed25519_dalek::Keypair;
// use ed25519_dalek::Signature;

fn main() {
    let mut csprng = OsRng::new().unwrap();
    let keypair = Keypair::generate(&mut csprng);
    let pk_b64 = base64::encode_config(keypair.public.as_bytes(), base64::STANDARD);
    let id = format!("@{}.ed25519", pk_b64);

    println!("id: {}", id);
}
