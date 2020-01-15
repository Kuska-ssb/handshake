extern crate base64;
extern crate hex;
extern crate rand;
extern crate sodiumoxide;

use std::convert::TryInto;

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign::ed25519;

fn main() {
    sodiumoxide::init().unwrap();

    let net_id_hex = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
    let net_id_slice = hex::decode(net_id_hex).unwrap();
    let net_id = auth::Key::from_slice(&net_id_slice[0..32]).unwrap();

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
    let (client_ephemeral_pk, client_ephemeral_sk) = (
        _client_ephemeral_pk.to_curve25519(),
        _client_ephemeral_sk.to_curve25519(),
    );
    {
        client_msg = [
            auth::authenticate(client_ephemeral_pk.as_ref(), &net_id).as_ref(),
            client_ephemeral_pk.as_ref(),
        ]
        .concat();
    }

    // 1.a Client Hello (Server)
    let server_client_ephemeral_pk = {
        assert!(client_msg.len() == 64);
        let client_hmac_buf = &client_msg[..32];
        let client_hmac = auth::Tag::from_slice(&client_hmac_buf.as_ref()[0..32]).unwrap();
        let client_ephemeral_pk_buf = &client_msg[32..];
        let client_ephemeral_pk =
            ed25519::PublicKey::from_slice(&client_ephemeral_pk_buf.as_ref()[0..32]).unwrap();
        if !auth::verify(&client_hmac, client_ephemeral_pk_buf, &net_id) {
            panic!("1. hmac verification at server failed");
        }
        client_ephemeral_pk
    };

    // 2.a Server Hello (Server)
    let (_server_ephemeral_pk, _server_ephemeral_sk) = ed25519::gen_keypair();
    let (server_ephemeral_pk, server_ephemeral_sk) = (
        _server_ephemeral_pk.to_curve25519(),
        _server_ephemeral_sk.to_curve25519(),
    );
    {
        server_msg = [
            auth::authenticate(server_ephemeral_pk.as_ref(), &net_id).as_ref(),
            server_ephemeral_pk.as_ref(),
        ]
        .concat();
    }

    // 2.b Server Hello (Client)
    let client_server_ephemeral_pk = {
        assert!(server_msg.len() == 64);
        let server_hmac_buf = &server_msg[..32];
        let server_hmac = auth::Tag::from_slice(&server_hmac_buf.as_ref()[0..32]).unwrap();
        let server_ephemeral_pk_buf = &server_msg[32..];
        let server_ephemeral_pk =
            ed25519::PublicKey::from_slice(&server_ephemeral_pk_buf.as_ref()[0..32]).unwrap();
        if !auth::verify(&server_hmac, server_ephemeral_pk_buf, &net_id) {
            panic!("2. hmac verification at server failed");
        }
        server_ephemeral_pk
    };

    // 2.c Server Hello, Shared secret derivation (Server)
    let server_shared_secret_ab = curve25519::scalarmult(
        &curve25519::Scalar(server_ephemeral_sk.0),
        &curve25519::GroupElement(server_client_ephemeral_pk.0),
    )
    .unwrap();
    let server_shared_secret_aB = curve25519::scalarmult(
        &curve25519::Scalar(server_sk.to_curve25519().0),
        &curve25519::GroupElement(server_client_ephemeral_pk.0),
    )
    .unwrap();
    // 2.d Server Hello, Shared secret derivation (Client)
    let client_shared_secret_ab = curve25519::scalarmult(
        &curve25519::Scalar(client_ephemeral_sk.0),
        &curve25519::GroupElement(client_server_ephemeral_pk.0),
    )
    .unwrap();
    let client_shared_secret_aB = curve25519::scalarmult(
        &curve25519::Scalar(client_ephemeral_sk.0),
        &curve25519::GroupElement(server_pk.to_curve25519().0),
    )
    .unwrap();

    // 3.a Client Authenticate (Client)
    let client_client_sig = {
        let sig = ed25519::sign_detached(
            &[
                net_id.as_ref(),
                server_pk.as_ref(),
                sha256::hash(client_shared_secret_ab.as_ref()).as_ref(),
            ]
            .concat(),
            &client_sk,
        );
        client_msg = secretbox::seal(
            &[sig.as_ref(), client_pk.as_ref()].concat(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        net_id.as_ref(),
                        client_shared_secret_ab.as_ref(),
                        client_shared_secret_aB.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        );
        sig
    };

    // 3.b Client Authenticate (Server)
    let (server_client_pk, server_client_sig) = {
        let msg = secretbox::open(
            client_msg.as_ref(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        net_id.as_ref(),
                        server_shared_secret_ab.as_ref(),
                        server_shared_secret_aB.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        )
        .unwrap();
        assert!(msg.len() == 96);
        let sig = ed25519::Signature::from_slice(&msg[0..64]).unwrap();
        let client_pk = ed25519::PublicKey::from_slice(&msg[64..32]).unwrap();
        if !ed25519::verify_detached(
            &sig,
            &[
                net_id.as_ref(),
                server_pk.as_ref(),
                sha256::hash(server_shared_secret_ab.as_ref()).as_ref(),
            ]
            .concat(),
            &client_pk,
        ) {
            panic!("3. signature verification failed");
        }
        (client_pk, sig)
    };

    // 3.c Client Authenticate, Shared secret derivation (Client)
    let client_shared_secret_Ab = curve25519::scalarmult(
        &curve25519::Scalar(client_sk.to_curve25519().0),
        &curve25519::GroupElement(client_server_ephemeral_pk.0),
    )
    .unwrap();
    // 3.d Client Authenticate, Shared secret derivation (Server)
    let server_shared_secret_Ab = curve25519::scalarmult(
        &curve25519::Scalar(server_ephemeral_sk.0),
        &curve25519::GroupElement(server_client_pk.to_curve25519().0),
    )
    .unwrap();

    // 4.a Server Accept (Server)
    {
        let sig = ed25519::sign_detached(
            &[
                net_id.as_ref(),
                server_client_sig.as_ref(),
                server_client_pk.as_ref(),
                sha256::hash(server_shared_secret_ab.as_ref()).as_ref(),
            ]
            .concat(),
            &server_sk,
        );
        server_msg = secretbox::seal(
            sig.as_ref(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        net_id.as_ref(),
                        server_shared_secret_ab.as_ref(),
                        server_shared_secret_aB.as_ref(),
                        server_shared_secret_Ab.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        );
    }

    // 4.b Server Accept (Client)
    {
        let msg = secretbox::open(
            server_msg.as_ref(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        net_id.as_ref(),
                        client_shared_secret_ab.as_ref(),
                        client_shared_secret_aB.as_ref(),
                        client_shared_secret_Ab.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        )
        .unwrap();
        assert!(msg.len() == 64);
        let sig = ed25519::Signature::from_slice(&msg[0..64]).unwrap();
        if !ed25519::verify_detached(
            &sig,
            &[
                net_id.as_ref(),
                client_client_sig.as_ref(),
                client_pk.as_ref(),
                sha256::hash(server_shared_secret_ab.as_ref()).as_ref(),
            ]
            .concat(),
            &server_pk,
        ) {
            panic!("4. signature verification failed");
        }
    }
}
