extern crate rand;
extern crate sodiumoxide;
extern crate base64;
extern crate hex;

use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::scalarmult::curve25519;

fn main() {
    sodiumoxide::init().unwrap();

    let net_id_hex = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
    let net_id_slice = hex::decode(net_id_hex).unwrap();
    let net_id = auth::Key::from_slice(&net_id_slice).unwrap();

    // Client
    let (client_pk, client_sk) = ed25519::gen_keypair();
    let client_pk_b64 = base64::encode_config(&client_pk, base64::STANDARD);
    let client_id = format!("@{}.ed25519", client_pk_b64);
    println!("client id: {}", client_id);

    // Server
    let (server_pk, server_sk) = ed25519::gen_keypair();
    let server_pk_b64 = base64::encode_config(&server_pk, base64::STANDARD);
    let server_id = format!("@{}.ed25519", server_pk_b64);
    println!("server id: {}", server_id);

    let mut client_msg = Vec::<u8>::new();
    let mut server_msg = Vec::<u8>::new();

    // 1.a Client Hello (Client)
    let (_client_ephemeral_pk, _client_ephemeral_sk) = ed25519::gen_keypair();
    let (client_ephemeral_pk, client_ephemeral_sk) = (_client_ephemeral_pk.to_curve25519(), _client_ephemeral_sk.to_curve25519());
    {
        client_msg = auth::authenticate(client_ephemeral_pk.as_ref(), &net_id).as_ref().to_vec();
        client_msg.extend_from_slice(client_ephemeral_pk.as_ref());
    }

    // 1.a Client Hello (Server)
    let server_client_ephemeral_pk =
    {
        let client_hmac_buf = &client_msg[..32];
        let client_hmac = auth::Tag::from_slice(client_hmac_buf).unwrap();
        let client_ephemeral_pk_buf = &client_msg[32..];
        let client_ephemeral_pk = ed25519::PublicKey::from_slice(client_ephemeral_pk_buf).unwrap();
        if !auth::verify(&client_hmac, client_ephemeral_pk_buf, &net_id) {
            panic!("1. hmac verification at server failed");
        }
        client_ephemeral_pk
    };

    // 2.a Server Hello (Server)
    let (_server_ephemeral_pk, _server_ephemeral_sk) = ed25519::gen_keypair();
    let (server_ephemeral_pk, server_ephemeral_sk) = (_server_ephemeral_pk.to_curve25519(), _server_ephemeral_sk.to_curve25519());
    {
        server_msg = auth::authenticate(server_ephemeral_pk.as_ref(), &net_id).as_ref().to_vec();
        server_msg.extend_from_slice(server_ephemeral_pk.as_ref());
    }

    // 2.b Server Hello (Client)
    let client_server_ephemeral_pk =
    {
        let server_hmac_buf = &server_msg[..32];
        let server_hmac = auth::Tag::from_slice(server_hmac_buf).unwrap();
        let server_ephemeral_pk_buf = &server_msg[32..];
        let server_ephemeral_pk = ed25519::PublicKey::from_slice(server_ephemeral_pk_buf).unwrap();
        if !auth::verify(&server_hmac, server_ephemeral_pk_buf, &net_id) {
            panic!("2. hmac verification at server failed");
        }
        server_ephemeral_pk
    };


    // 2.c Server Hello, SHared secret derivation (Server)
    let server_shared_secret_ab = curve25519::scalarmult(
        &curve25519::Scalar::from_slice(server_ephemeral_sk.as_ref()).unwrap(),
        &curve25519::GroupElement::from_slice(server_client_ephemeral_pk.as_ref()).unwrap());
    let server_shared_secret_aB = curve25519::scalarmult(
        &curve25519::Scalar::from_slice(server_sk.to_curve25519().as_ref()).unwrap(),
        &curve25519::GroupElement::from_slice(server_client_ephemeral_pk.as_ref()).unwrap());
    // 2.d Server Hello, SHared secret derivation (Client)
    let client_shared_secret_ab = curve25519::scalarmult(
        &curve25519::Scalar::from_slice(client_ephemeral_sk.as_ref()).unwrap(),
        &curve25519::GroupElement::from_slice(client_server_ephemeral_pk.as_ref()).unwrap());
    let client_shared_secret_aB = curve25519::scalarmult(
        &curve25519::Scalar::from_slice(client_ephemeral_sk.as_ref()).unwrap(),
        &curve25519::GroupElement::from_slice(server_pk.to_curve25519().as_ref()).unwrap());
}
