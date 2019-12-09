use super::IdentitySecret;
use crate::pasync::crypto::ToSodiumObject;

use sodiumoxide::crypto::sign::{PublicKey,SecretKey};
use crate::pasync::util::to_ioerr;
use sodiumoxide::crypto::{hash::sha256, auth, sign::ed25519, scalarmult::curve25519, secretbox};
use async_std::io;

const SUFFIX : &str = ".box";

pub fn is_privatebox(text : &str) -> bool {
    text.ends_with(SUFFIX) 
}

pub fn privatebox_cipher(plaintext : &str, recipients: &[&str]) -> Result<String,io::Error> {
    let recipients : Result<Vec<_>,_> = recipients
        .into_iter()
        .map(|id| {
            id[1..].to_ed25519_pk()
        }).collect();

    let recipients=recipients
        .map_err(|_| to_ioerr("failed parse recipients"))?;
    
    let recipients_ref : Vec<_> =
        recipients.iter().map(|r| r).collect();    

    let ciphertext = cipher(plaintext.as_bytes(),&recipients_ref[..])?;

    Ok(format!("{}{}",base64::encode(&ciphertext),SUFFIX))
} 

pub fn privatebox_decipher(ciphertext : &str, sk : &SecretKey) -> Result<Option<String>,io::Error> {
    let msg = &ciphertext.as_bytes()[..ciphertext.len()-SUFFIX.len()];
    let msg = base64::decode(msg).map_err(to_ioerr)?;

    let plaintext = decipher(&msg, &sk)?
        .map(|msg| String::from_utf8_lossy(&msg).to_string());

    Ok(plaintext)
} 

fn cipher(plaintext : &[u8], recipients : &[&ed25519::PublicKey]) -> Result<Box<[u8]>,io::Error> {
    // Precondition checks
    if plaintext.is_empty() {
        return Err(to_ioerr("message cannot be empty when encrypting"));
    }

    if recipients.len() == 0 || recipients.len() > 7 {
        return Err(to_ioerr("bad number of recipients when encrypting"));
    }

    // Generated Curve25519 key pair to encrypt message header
    let (h_pk, h_sk) = ed25519::gen_keypair();

    // Generated random 32-byte secret key used to encrypt the message body
    let y = sodiumoxide::crypto::secretbox::gen_key();
  
    // Encrypt the plaintext with y, with a random nonce
    let nonce = secretbox::gen_nonce();
    let cipher_message = secretbox::seal(plaintext, &nonce, &y);

    // The sender uses scalar multiplication to derive a shared secret for each recipient,
    //   and encrypts (number_of_recipents || y) for each one
    let h_sk_scalar = &h_sk.to_curve25519();
    let mut plain_header = [0u8;33];
    plain_header[0]=recipients.len() as u8;
    &plain_header[1..].copy_from_slice(&y[..]);

    let mut buffer : Vec<u8> = Vec::with_capacity(   
        24  // nonce
        +32 // header public key
        +49*recipients.len() // encrypted headers for each recipient
        +16+plaintext.len() // tag + encrypted message contenth 
    );

    buffer.extend_from_slice(&nonce[..]);
    buffer.extend_from_slice(&h_pk.to_curve25519()[..]);
    for recipient in recipients {
        let key = curve25519::scalarmult(&h_sk_scalar, &recipient.to_curve25519())
            .map_err(|_| to_ioerr("scalarmult failed"))?;

        let key = secretbox::Key::from_slice(&key[..])
            .ok_or(to_ioerr("key from group failed"))?;

        buffer.extend_from_slice(&secretbox::seal(&plain_header[..],&nonce, &key));
    }
    buffer.extend_from_slice(&cipher_message[..]);
    Ok(buffer.into_boxed_slice())
}

fn decipher(ciphertext : &[u8], sk : &SecretKey) -> Result<Option<Vec<u8>>,io::Error> {

    let nonce = secretbox::Nonce::from_slice(&ciphertext[..secretbox::NONCEBYTES])
        .ok_or(to_ioerr("cannot read nonce"))?;

    let h_pk = curve25519::GroupElement::from_slice(&ciphertext[secretbox::NONCEBYTES..secretbox::NONCEBYTES+32])
        .ok_or(to_ioerr("cannot convert to curve"))?;
    
    let key = curve25519::scalarmult(&sk.to_curve25519(), &h_pk)
        .map_err(|_| to_ioerr("cannot scalarmult"))?;

    let key = secretbox::Key::from_slice(&key[..])
        .ok_or(to_ioerr("cannot create key"))?;

    let mut cursor = &ciphertext[secretbox::NONCEBYTES+32..];
    let mut header_no = 0;
    while header_no < 7 && cursor.len() >= 49+17 {
        if let Ok(header) = secretbox::open(&cursor[..49], &nonce, &key) {
            let encrypted_message_offset = 49*(header[0]-header_no) as usize;
            let y =  secretbox::Key::from_slice(&header[1..])
                .ok_or(to_ioerr("cannot create key"))?;
            let plaintext = secretbox::open(&cursor[encrypted_message_offset..], &nonce, &y)
                .map_err(|_| to_ioerr("failed to decipher"))?;
            return Ok(Some(plaintext));
        }
        header_no += 1;
        cursor = &cursor[49..];
    }

    Ok(None)
}

mod test {
    use super::*;
    
    #[test]
    fn test_msg_cipher_to_one() -> Result<(),io::Error> {
        let (u1_pk, u1_sk) = ed25519::gen_keypair();
        let plaintext = "hola".as_bytes();
        let ciphertext = cipher(plaintext, &[&u1_pk])?;
        let plaintext_1 = decipher(&ciphertext, &u1_sk)?.unwrap();
        assert_eq!(plaintext.to_vec(),plaintext_1);
        Ok(())
    }

    #[test]
    fn test_msg_cipher_to_one_helper() -> Result<(),io::Error> {
        let id = IdentitySecret::new();
        let plaintext = "holar";
        let ciphertext = privatebox_cipher(plaintext, &[&id.id])?;
        assert_eq!(is_privatebox(&ciphertext),true);
        let plaintext_1 = privatebox_decipher(&ciphertext, &id.sk)?.unwrap();
        assert_eq!(plaintext,plaintext_1);
        Ok(())
    }

    #[test]
    fn test_msg_cipher_to_none() -> Result<(),io::Error> {
        let (u1_pk, _) = ed25519::gen_keypair();
        let (_, u1_sk) = ed25519::gen_keypair();
        let plaintext = "hola".as_bytes();
        let ciphertext = cipher(plaintext, &[&u1_pk])?;
        let plaintext_1 = decipher(&ciphertext, &u1_sk)?;
        assert_eq!(None,plaintext_1);
        Ok(())
    }

    #[test]
    fn test_msg_cipher_to_multiple() -> Result<(),io::Error> {
        let u = (0..7).map(|_| ed25519::gen_keypair()).collect::<Vec<_>>();
        let u_pk = u.iter().map(|(pk,_)| pk).collect::<Vec<_>>();

        let plaintext = "hola".as_bytes();
        let ciphertext = cipher(plaintext, &u_pk)?;

        for (_,sk) in u.iter() {
            let plaintext_1 = decipher(&ciphertext, sk)?.unwrap();
            assert_eq!(plaintext.to_vec(),plaintext_1);    
        }

        Ok(())
    }

    #[test]
    fn test_cipher_mine() -> Result<(),io::Error> {
        let msg = r#"E7AiHjdnail0QakQjw/4PTqwQE8HSr/zU/JgZIWvz+03l4pAEbwIAmmhHImFLa6zGAJpoxnDvVt7ycXGJ+XocT83LZhbG9HwS3nSRsQfKzREg/Ho3rWxKAzbJo8euNM3GtcxM/Qj6o2/AU9Sz6RdLe7X/Dnv+NxFDLJrwMOEp4NjlWHjfdxhqCzv6r3F+0a45vL5soPdyWPBy+Zq8lydfiE/Hhrkou/DwQEZcfMgaLu0mRL4umzv/IsJJiMaA78nJs6hsgQZYuunaa/jNKKRNa7fB+IGzILaA5D6Q+FOCDZPT6n43XE/IimNa+OQSXtnctOildPLwMWNjD0+aKsUPQN5ABlUQjP8dewrQ83T1fxd+ospqyVwQF0tU+q1SvNraFZREhJ6njrbTEnQWfQqsRu7djnLI64edNbDhypagYVWQ2PWXq05wEKsAwYqY8auzbCCFXyVvLhSvRM1YH7Ue/bWNiFSUgJGBhSYfoy8ugdGhNsgmsSRtmjVQmH3uDuc4uaKZU20wqzIvNCNrmJ02iMa1kTjjBggN6fak4csmtr5muogz7hoFCSCB7jAMdiPusi4SHoCWR8eXir8szyKQJn9FPNZwejX0crVUOWX9E3JzK7s7Qw6kcIEBFqOdLzYBJ7hdTh6uVtKjDjtIUji6HoWmxUAj3DG6wUUxGB+ScFylU7bp/87R3cfdZZ35FiCh2MVM9OYAmMfzfp545LJzqhzB+F7uGTcVi4YCZ7ztE4UEgUHhB7Hi/kfctP6x/9gT5LhFHsO0FmTF46kwAzKuOs1f1rhL7pziVJX2RvLThX1A20DjoysTocgXN/ee8qLIDeEJVAc9EwC1P36na1I1npIewFH20WScdES6z85zYlNxQDfhdXaaHOqjGsF5PJj4U8=.box"#;
        let msg = &msg.as_bytes()[..msg.len()-SUFFIX.len()];
        let msg = base64::decode(msg).map_err(to_ioerr)?;

        println!("{:?}",msg.len());

        let id = IdentitySecret::from_local_config()?;
        let wat = decipher(&msg, &id.sk)?.unwrap();

        println!("***********{:?}",String::from_utf8_lossy(&wat));

        Ok(())
    }
}