use crate::pasync::util::to_ioerr;
use crate::pasync::crypto::ToSodiumObject;

use sodiumoxide::crypto::{hash::sha256, sign::ed25519};
use async_std::io;

pub fn verify_feed_integrity(feed: &str) -> Result<(),io::Error>{

    let feed: serde_json::Value = serde_json::from_str(feed).map_err(to_ioerr)?;

    // verify message described key
    let mut root = match feed {
        serde_json::Value::Object(values) => values,
        _ => return Err(to_ioerr("bad feed base type"))        
    };

    let key = match root.remove("key") {
        Some(serde_json::Value::String(key)) => {
            let key = &key[1..];
            key.to_sha256()?
        },
        _ => return Err(to_ioerr("bad feed key type"))        
    };

    let value = root.remove("value")
        .ok_or(to_ioerr("value not found"))?;

    let expected_key = sha256::hash(stringify_json(&value)?.as_bytes());

    if key != expected_key {
        return Err(to_ioerr("cannot check message key"));
    }

    // verify message signature
    let mut value = match value {
        serde_json::Value::Object(value) => value,
        _ => return Err(to_ioerr("bad feed key value"))        
    };

    let signature = match value.remove("signature") {
        Some(serde_json::Value::String(sig)) => sig.to_ed25519_signature()?,
        _ => return Err(to_ioerr("bad feed signature type"))        
    };

    let author = match value.get("author") {
        Some(serde_json::Value::String(a)) => {
            let pk = &a[1..]; 
            pk.to_ed25519_pk()?
        },
        _ => return Err(to_ioerr("bad feed value type"))        
    };
        
    let message = stringify_json(&serde_json::Value::Object(value))?;

    if !ed25519::verify_detached(&signature, &message.as_ref(), &author) {
        return Err(to_ioerr("signature verification failed"));
    }

    Ok(())
}

fn stringify_json(v: &serde_json::Value) -> Result<String, io::Error> {
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
    fn append_json(buffer: &mut String, level : usize, v: &serde_json::Value) -> Result<(), io::Error> {
        match v {
            serde_json::Value::Object(values) => {
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
            serde_json::Value::Array(values) => {
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
            serde_json::Value::String(value) => {
                append_string(buffer, value);
            }
            serde_json::Value::Number(value) => {
                buffer.push_str(&value.to_string());
            }
            serde_json::Value::Bool(value) => {
                buffer.push_str(if *value { "true" } else { "false" });
            }
            serde_json::Value::Null => {
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
    #[test]
    fn test_json_stringify() -> Result<(),io::Error>{
        let json = r#"{"a":0,"b":1.1,"c":null,"d":true,"f":false,"g":{},"h":{"h1":1},"i":[],"j":[1],"k":[1,2]}"#;
        let v: serde_json::Value = serde_json::from_str(json).map_err(to_ioerr)?;
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
        verify_feed_integrity(&feed)
    }
}