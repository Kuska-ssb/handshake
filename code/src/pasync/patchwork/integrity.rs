use crate::pasync::util::to_ioerr;
use crate::pasync::crypto::ToSodiumObject;
use crate::pasync::patchwork::IdentitySecret;

use sodiumoxide::crypto::{hash::sha256, sign::ed25519};
use async_std::io;
use serde_json::Value;
use super::dto::{Feed, FeedValue};
use std::time::SystemTime;

macro_rules! cast {
    ($input:expr,$pth:path) => {
        match $input {
            Some($pth(x)) => Ok(x),
            _ => Err(to_ioerr(format!("cannot cast {} to {}",stringify!($input),stringify!($pth))))       
        };
    }
}

macro_rules! cast_opt {
    ($input:expr,$pth:path) => {
        match $input {
            None => Ok(None),
            Some($pth(x)) => Ok(Some(x)),
            _ => Err(to_ioerr(format!("cannot cast {} to {}",stringify!($input),stringify!($pth))))       
        };
    }
}

impl Feed {

    pub fn sign(content : Value, identity : &IdentitySecret, previous: Option<String>, next_seq: u64) -> Result<String,io::Error> {

        let mut value : serde_json::Map<String,Value> = serde_json::Map::new();
        if let Some(previous) = previous {
            value.insert("previous".to_string(),Value::String(previous));
        }

        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .map_err(to_ioerr)?.as_millis() as u64;
        let timestamp = Value::Number(serde_json::Number::from(timestamp));

        value.insert(
            "author".to_string(),
            Value::String(identity.id.clone())
        );
        value.insert(
            "sequence".to_string(),
            Value::Number(serde_json::Number::from(next_seq))
        );
        value.insert(
            "timestamp".to_string(),
            timestamp.clone()
        );
        value.insert(
            "hash".to_string(),
            Value::String("sha256".to_string())
        );
        value.insert(
            "content".to_string(),
            content
        );

        let value = Value::Object(value);
        let to_sign_text = stringify_json(&value)?;
        let mut value = cast!(Some(value),Value::Object)?;

        let signature = ed25519::sign_detached(to_sign_text.as_bytes(), &identity.sk);
        value.insert(
            "signature".to_string(),
            Value::String(format!("{}.sig.ed25519",base64::encode(&signature)))
        );

        let value = Value::Object(value);
        let key = sha256::hash(stringify_json(&value)?.as_bytes());

        let mut feed : serde_json::Map<String,Value> = serde_json::Map::new();
        feed.insert(
            "key".to_string(),
            Value::String(format!("%{}.sha256",base64::encode(&key)))
        );
        feed.insert(
            "value".to_string(),
            value
        );
        feed.insert(
            "timestamp".to_string(),
            timestamp.clone()
        );

        let encoded = Value::Object(feed).to_string();

        Ok(encoded)
    }


    pub fn from_str(feed: &str) -> Result<Feed,io::Error>{

        // TODO: check optimizations, maybe so messy

        let feed: Value = serde_json::from_str(feed).map_err(to_ioerr)?;

        // verify message described key
        let mut feed = cast!(Some(feed),Value::Object)?;

        let feed_key = cast!(feed.remove("key"),Value::String)?;
        let feed_timestamp = cast!(feed.remove("timestamp"),Value::Number)?
            .as_f64().ok_or(to_ioerr("invalid timestamp f64"))?;
        let feed_rts = cast_opt!(feed.remove("rts"),Value::Number)?
            .map(|v| v.as_f64().unwrap()); // TODO(amb) FIX

        let feed_value = feed.remove("value").ok_or(to_ioerr("feed value not found"))?;
        let feed_value_digest = sha256::hash(stringify_json(&feed_value)?.as_bytes());
        if feed_key[1..].to_sha256()? != feed_value_digest {
            return Err(to_ioerr("cannot check message key"));
        }

        let mut feed_value = cast!(Some(feed_value),Value::Object)?;

        // verify message signature
        let value_signature = cast!(feed_value.remove("signature"),Value::String)?;

        let feed_value = Value::Object(feed_value);
        let signed_text = stringify_json(&feed_value)?;
        let mut feed_value = cast!(Some(feed_value),Value::Object)?;

        let value_previous = cast_opt!(feed_value.remove("previous"),Value::String)?;
        let value_author = cast!(feed_value.remove("author"),Value::String)?;
        let value_sequence = cast!(feed_value.remove("sequence"),Value::Number)?
            .as_u64().ok_or(to_ioerr("invalid sequence u64"))?;
        let value_timestamp = cast!(feed_value.remove("timestamp"),Value::Number)?
            .as_f64().ok_or(to_ioerr("invalid timestamp f64"))?;
        let value_hash = cast!(feed_value.remove("hash"),Value::String)?;
        let value_content = feed_value.remove("content").ok_or(to_ioerr("content not exist"))?;

        let signature = value_signature.to_ed25519_signature()?;
        let signer = value_author[1..].to_ed25519_pk()?;

        if !ed25519::verify_detached(&signature, &signed_text.as_ref(), &signer) {
            return Err(to_ioerr("signature verification failed"));
        }

        Ok(Feed {
            key : feed_key,
            timestamp : feed_timestamp,
            rts : feed_rts,
            value : FeedValue {
                previous : value_previous,
                author : value_author,
                sequence : value_sequence,
                timestamp : value_timestamp,
                hash : value_hash,
                content: value_content,
                signature: value_signature,
            }
        })
    }
}

fn stringify_json(v: &Value) -> Result<String, io::Error> {
    fn spaces(n: usize) -> &'static str {
        &"                                         "[..2*n]
    }
    // see https://www.ecma-international.org/ecma-262/6.0/#sec-quotejsonstring
    fn append_string(buffer: &mut String, s: &str) {
        buffer.push('"');
        s.chars().for_each(|ch| match ch {
            '"' | '\\' => { buffer.push('\\'); buffer.push(ch) },
            '\x08' => buffer.push_str("\\b"),
            '\x0c' => buffer.push_str("\\f"),
            '\n' => buffer.push_str("\\n"),
            '\r' => buffer.push_str("\\r"),
            '\t' => buffer.push_str("\\t"),
            _ if (ch as u32) < 0x20 => buffer.push_str(&format!("\\u{}", ch as u32)),
            _ => buffer.push(ch),
        });
        buffer.push('"');
    }
    // see https://www.ecma-international.org/ecma-262/6.0/#sec-serializejsonobject
    fn append_json(buffer: &mut String, level : usize, v: &Value) -> Result<(), io::Error> {
        match v {
            Value::Object(values) => {
                if values.is_empty() {
                    buffer.push_str("{}");
                } else {
                    buffer.push_str("{\n");
                    for (i, (key, value)) in values.iter().enumerate() {
                        buffer.push_str(spaces(level+1));
                        append_string(buffer, key);
                        buffer.push_str(": ");
                        append_json(buffer, level+1, &value)?;
                        if i < values.len() - 1 {
                            buffer.push(',');
                        }
                        buffer.push('\n');
                    }
                    buffer.push_str(spaces(level));
                    buffer.push('}');    
                }
            }
            Value::Array(values) => {
                if values.is_empty() {
                    buffer.push_str("[]");
                } else {
                    buffer.push_str("[\n");
                    for (i, value) in values.iter().enumerate() {
                        buffer.push_str(spaces(level+1));
                        append_json(buffer, level+1, &value)?;
                        if i < values.len() - 1 {
                            buffer.push(',');
                        }
                        buffer.push('\n');
                    }
                    buffer.push_str(spaces(level));
                    buffer.push(']');
                }
            }
            Value::String(value) => {
                append_string(buffer, value);
            }
            Value::Number(value) => {
                buffer.push_str(&value.to_string());
            }
            Value::Bool(value) => {
                buffer.push_str(if *value { "true" } else { "false" });
            }
            Value::Null => {
                buffer.push_str("null");
            }
        }
        Ok(())
    }
    let mut result = String::new();
    append_json(&mut result, 0, &v)?;
    Ok(result)
}

mod test {
    use super::*;
    
    const JSON : &str = r#"{"a":0,"b":1.1,"c":null,"d":true,"f":false,"g":{},"h":{"h1":1},"i":[],"j":[1],"k":[1,2]}"#; 
    
    #[test]
    fn test_json_stringify() -> Result<(),io::Error>{
        let v: Value = serde_json::from_str(JSON).map_err(to_ioerr)?;
        let json = stringify_json(&v)?;
        let expected = 
r#"{
  "a": 0,
  "b": 1.1,
  "c": null,
  "d": true,
  "f": false,
  "g": {},
  "h": {
    "h1": 1
  },
  "i": [],
  "j": [
    1
  ],
  "k": [
    1,
    2
  ]
}"#;

    assert_eq!(expected,json);
    Ok(())
    }
    
    #[test]
    fn test_verify_feed_integrity() -> Result<(),io::Error> {
        let feed = r#"{"key":"%Cg0ZpZ8cV85G8UIIropgBOvM8+Srlv9LSGDNGnpdK44=.sha256","value":{"previous":"%seUEAo7PTyA7vNwnOrmGIsUFfpyRzOvzGVv1QCb/Fz8=.sha256","author":"@BIbVppzlrNiRJogxDYz3glUS7G4s4D4NiXiPEAEzxdE=.ed25519","sequence":37,"timestamp":1439392020612,"hash":"sha256","content":{"type":"post","text":"@paul real time replies didn't work.","repliesTo":"%xWKunF6nXD7XMC+D4cjwDMZWmBnmRu69w9T25iLNa1Q=.sha256","mentions":["%7UKRfZb2u8al4tYWHqM55R9xpE/KKVh9U0M6BdugGt4=.sha256"],"recps":[{"link":"@hxGxqPrplLjRG2vtjQL87abX4QKqeLgCwQpS730nNwE=.ed25519","name":"paul"}]},"signature":"gGxSPdBJZxp6x5f3HzQGoQSeSdh/C5AtymIn+miWa+lcC6DdqpRSgaeH9KHeLf+/CKhU6REYIpWaLr4CKDMfCg==.sig.ed25519"},"timestamp":1573574678194,"rts":1439392020612}"#;
        Feed::from_str(&feed)?;
        Ok(())
    }

    #[test]
    fn test_sign_verify() -> Result<(),io::Error> {
        let id = IdentitySecret::new();
        let content: Value = serde_json::from_str(JSON).map_err(to_ioerr)?;
        let signed_feed = Feed::sign(content,&id,None,1)?;
        println!("{}",signed_feed);
        Feed::from_str(&signed_feed)?;
        Ok(())
    }
    
}