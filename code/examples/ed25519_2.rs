extern crate rand;
extern crate sodiumoxide;
extern crate base64;

use sodiumoxide::crypto::sign::ed25519;

fn main() {
    sodiumoxide::init().unwrap();
    let (pk, sk) = ed25519::gen_keypair();
    let pk_b64 = base64::encode_config(&pk, base64::STANDARD);
    let id = format!("@{}.ed25519", pk_b64);

    println!("id: {}", id);
}
