use sodiumoxide::crypto::sign::ed25519;
use std::io;
use base64;
use std::string::ToString;
use sodiumoxide::crypto::auth;

const CURVE_ED25519 : &str = "ed25519";
const CURVE_ED25519_SUFFIX : &str = ".ed25519";
const SSB_NET_ID : &str = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";

#[derive(Debug)]
pub struct IdentitySecret {
    pub id: String,
    pub pk: ed25519::PublicKey,
    pub sk: ed25519::SecretKey,
}

#[derive(Deserialize)]
struct JsonSSBSecret {
    id: String,
    curve: String,
    public: String,
    private: String,
}

pub fn ssb_net_id() -> auth::Key {
    auth::Key::from_slice(&hex::decode(SSB_NET_ID).unwrap()).unwrap()
}

fn to_ioerr<T: ToString>(err: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn to_ed25519_pk(s : &str) -> io::Result<ed25519::PublicKey> {
    if !s.ends_with(CURVE_ED25519_SUFFIX) {
        return Err(to_ioerr("invalid suffix"));
    }

    let key_len = s.len()-CURVE_ED25519_SUFFIX.len();
    let bytes = base64::decode(&s[..key_len])
        .map_err(to_ioerr)?;
    
    ed25519::PublicKey::from_slice(&bytes)
        .ok_or_else(|| to_ioerr("bad public key"))
}

fn to_ed25519_sk(s : &str) -> io::Result<ed25519::SecretKey> {
    if !s.ends_with(CURVE_ED25519_SUFFIX) {
        return Err(to_ioerr("invalid suffix"));
    }

    let key_len = s.len()-CURVE_ED25519_SUFFIX.len();
    let bytes = base64::decode(&s[..key_len]).map_err(to_ioerr)?;

    ed25519::SecretKey::from_slice(&bytes)
        .ok_or_else(|| to_ioerr("bad secret key"))
}

impl IdentitySecret {

    pub fn from_local_config() -> io::Result<IdentitySecret> {
        if let Some(home_dir) = dirs::home_dir() {
            let local_key_file = format!("{}/.ssb/secret",home_dir.to_string_lossy());

            std::fs::read_to_string(local_key_file)
                .and_then(IdentitySecret::from_config)

        } else {
            Err(to_ioerr("cannot retrieve home folder"))
        }
    }

    pub fn from_config<T : AsRef<str>>(config: T) -> io::Result<IdentitySecret> {

        // strip all comments
        let json = config.as_ref()
            .lines()
            .filter(|line| !line.starts_with("#"))
            .collect::<Vec<_>>()
            .join("");

        // parse json
        let secret : JsonSSBSecret = serde_json::from_str(json.as_ref())
            .map_err(to_ioerr)?;

        if secret.curve != CURVE_ED25519 {
            return Err(to_ioerr("invalid curve"));
        }
        
        Ok(IdentitySecret {
            id : secret.id,
            pk : to_ed25519_pk(&secret.public)?,
            sk : to_ed25519_sk(&secret.private)?,
        })
    } 
}