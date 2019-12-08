use async_std::io::{self, Read, Write};
use serde_json;
use std::collections::HashMap;
use sodiumoxide::crypto::{hash::sha256, sign::ed25519};

use super::asyncrpc::RpcClient;
use super::asyncrpc::{Header, RequestNo, RpcType};
use super::asyncutil::to_ioerr;
use super::sodiumutil::ToSodiumObject;

pub type SsbHashType = String;
pub type SsbHash = String;
pub type SsbId = String;
pub type SsbChannel = String;
pub type SsbSignature = String;


#[derive(Debug, Deserialize)]
struct ErrorRes {
    pub name: String,
    pub message: String,
    pub stack: String,
}

// https://github.com/ssbc/ssb-db/blob/master/api.md
#[derive(Debug, Serialize)]
pub struct CreateStreamArgs<K> {
    /// live (boolean, default: false): Keep the stream open and emit new messages as they are received
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,

    /// gt (greater than), gte (greater than or equal) define the lower bound of the range to be streamed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gt: Option<K>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gte: Option<K>,

    /// lt (less than), lte (less than or equal) define the higher bound of the range to be streamed. Only key/value pairs where the key is less than (or equal to) this option will be included in the range. When reverse=true the order will be reversed, but the records streamed will be the same.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lt: Option<K>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lte: Option<K>,

    /// reverse (boolean, default: false): a boolean, set true and the stream output will be reversed. Beware that due to the way LevelDB works, a reverse seek will be slower than a forward seek.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse: Option<bool>,

    /// keys (boolean, default: true): whether the data event should contain keys. If set to true and values set to false then data events will simply be keys, rather than objects with a key property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<bool>,

    /// values (boolean, default: true): whether the data event should contain values. If set to true and keys set to false then data events will simply be values, rather than objects with a value property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<bool>,

    /// limit (number, default: -1): limit the number of results collected by this stream. This number represents a maximum number of results and may not be reached if you get to the end of the data first. A value of -1 means there is no limit. When reverse=true the highest keys will be returned instead of the lowest keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,

    /// fillCache (boolean, default: false): wheather LevelDB's LRU-cache should be filled with data read.
    #[serde(rename = "fillCache")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_cache: Option<bool>,
    /// keyEncoding / valueEncoding (string): the encoding applied to each read piece of data.
    #[serde(rename = "keyEncoding")]
    pub key_encoding: Option<String>,

    #[serde(rename = "valueEncoding")]
    pub value_encoding: Option<String>,
}

impl<K> Default for CreateStreamArgs<K> {
    fn default() -> Self {
        Self {
            live: None,
            gt: None,
            gte: None,
            lt: None,
            lte: None,
            reverse: None,
            keys: None,
            values: None,
            limit: None,
            fill_cache: None,
            key_encoding: None,
            value_encoding: None,
        }
    }
}

impl<K> CreateStreamArgs<K> {
    pub fn live(self: Self, live: bool) -> Self {
        Self {
            live: Some(live),
            ..self
        }
    }
    pub fn gt(self: Self, v: K) -> Self {
        Self {
            gt: Some(v),
            ..self
        }
    }
    pub fn gte(self: Self, v: K) -> Self {
        Self {
            gte: Some(v),
            ..self
        }
    }
    pub fn lt(self: Self, v: K) -> Self {
        Self {
            lt: Some(v),
            ..self
        }
    }
    pub fn lte(self: Self, v: K) -> Self {
        Self {
            lte: Some(v),
            ..self
        }
    }
    pub fn reverse(self: Self, reversed: bool) -> Self {
        Self {
            reverse: Some(reversed),
            ..self
        }
    }
    pub fn keys_values(self: Self, keys: bool, values: bool) -> Self {
        Self {
            keys: Some(keys),
            values: Some(values),
            ..self
        }
    }
    pub fn encoding(self: Self, keys: String, values: String) -> Self {
        Self {
            key_encoding: Some(keys),
            value_encoding: Some(values),
            ..self
        }
    }
    pub fn limit(self: Self, limit: u64) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateHistoryStreamArgs<'a> {
    // id (FeedID, required): The id of the feed to fetch.
    pub id: &'a str,

    /// (number, default: 0): If seq > 0, then only stream messages with sequence numbers greater than seq.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,

    /// live (boolean, default: false): Keep the stream open and emit new messages as they are received
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
    /// keys (boolean, default: true): whether the data event should contain keys. If set to true and values set to false then data events will simply be keys, rather than objects with a key property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<bool>,

    /// values (boolean, default: true): whether the data event should contain values. If set to true and keys set to false then data events will simply be values, rather than objects with a value property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<bool>,

    /// limit (number, default: -1): limit the number of results collected by this stream. This number represents a maximum number of results and may not be reached if you get to the end of the data first. A value of -1 means there is no limit. When reverse=true the highest keys will be returned instead of the lowest keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

impl<'a> CreateHistoryStreamArgs<'a> {
    pub fn new(id: &'a str) -> Self {
        Self {
            id,
            seq: None,
            live: None,
            keys: None,
            values: None,
            limit: None,
        }
    }
    pub fn from_seq(self: Self, seq: u64) -> Self {
        Self {
            seq: Some(seq),
            ..self
        }
    }
    pub fn live(self: Self, live: bool) -> Self {
        Self {
            live: Some(live),
            ..self
        }
    }
    pub fn keys_values(self: Self, keys: bool, values: bool) -> Self {
        Self {
            keys: Some(keys),
            values: Some(values),
            ..self
        }
    }
    pub fn limit(self: Self, limit: u64) -> Self {
        Self {
            limit: Some(limit),
            ..self
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WhoAmI {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct Mention {
    pub link: SsbId,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MessageContent {
    #[serde(rename = "type")]
    pub xtype: String,
    pub text: String,
    pub mentions: Option<Vec<Mention>>,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub previous: Option<String>,
    pub sequence: u64,
    pub author: String,
    pub timestamp: u64,
    pub hash: String,
    pub content: MessageContent,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct PubAddress {
    pub host: Option<String>,
    pub port: u16,
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VoteValue {
    Numeric(i64),
    Boolean(bool),
}

#[derive(Debug, Deserialize)]
pub struct Vote {
    link: SsbHash,
    value: VoteValue,
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Image {
    OnlyLink(SsbHash),
    Complete {
        link: SsbHash,
        name: Option<String>,
        size: u64,
        width: Option<u32>,
        height: Option<u32>,
        #[serde(rename = "type")]
        content_type: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct DateTime {
    epoch: u64,
    tz: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Branch {
    One(SsbHash),
    Many(Vec<SsbHash>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Mentions {
    Link(SsbHash),
    One(Mention),
    Vector(Vec<Mention>),
    Map(HashMap<String, Mention>),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum FeedTypedContent {
    #[serde(rename = "pub")]
    Pub { address: Option<PubAddress> },
    #[serde(rename = "post")]
    Post {
        text: Option<String>,
        post: Option<String>, // the same than text
        channel: Option<String>,
        mentions: Option<Mentions>,
        root: Option<SsbHash>,
        branch: Option<Branch>,
        reply: Option<HashMap<SsbHash, SsbId>>,
        recps: Option<String>,
    },
    #[serde(rename = "contact")]
    Contact {
        contact: Option<SsbId>,
        blocking: Option<bool>,
        following: Option<bool>,
        autofollow: Option<bool>,
    },
    #[serde(rename = "about")]
    About {
        about: SsbId,
        name: Option<String>,
        title: Option<String>,
        branch: Option<SsbHash>,
        image: Option<Image>,
        description: Option<String>,
        location: Option<String>,
        #[serde(rename = "startDateTime")]
        start_datetime: Option<DateTime>,
    },
    #[serde(rename = "channel")]
    Channel { channel: String, subscribed: bool },
    #[serde(rename = "vote")]
    Vote { vote: Vote },
    /*
    #[serde(rename = "gathering")]
    Gathering,
    #[serde(rename = "post-edit")]
    PostEdit,
    #[serde(rename = "git-update")]
    GitUpdate,
    #[serde(rename = "git-repo")]
    GitRepo,
    #[serde(rename = "flag")]
    Flag,
    #[serde(rename = "append")]
    Append,
    #[serde(rename = "from")]
    From,
    #[serde(rename = "issue")]
    Issue,
    #[serde(rename = "pull-request")]
    PullRequest,
    #[serde(rename = "event")]
    Event,
    #[serde(rename = "issue-edit")]
    IssueEdit,
    #[serde(rename = "meta-data")]
    MetaData,
    #[serde(rename = "meta-image")]
    MetaImage,
    */
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum FeedContent {
    Untyped(String),
    Typed(FeedTypedContent),
}

#[derive(Debug, Deserialize)]
pub struct FeedValue {
    pub previous: Option<SsbHash>,
    pub author: SsbId,
    pub sequence: u64,
    pub timestamp: f64,
    pub hash: SsbHashType,
    pub content: FeedContent,
    pub signature: SsbSignature,
}

#[derive(Debug, Deserialize)]
pub struct Feed {
    pub key: SsbHash,
    pub value: FeedValue,
    pub timestamp: f64,
    pub rts: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct LatestUserMessage {
    pub id: SsbId,
    pub sequence: u64,
    pub ts: u64,
}

fn parse_json<'a, T: serde::Deserialize<'a>>(
    header: &'a Header,
    body: &'a Vec<u8>,
) -> Result<T, io::Error> {
    if header.is_end_or_error {
        let error: ErrorRes = serde_json::from_slice(&body[..]).map_err(to_ioerr)?;
        Err(to_ioerr(format!("{:?}", error)))
    } else {
        let res: T = serde_json::from_slice(&body[..]).map_err(to_ioerr)?;
        Ok(res)
    }
}

pub fn parse_whoami(header: &Header, body: &Vec<u8>) -> Result<WhoAmI, io::Error> {
    parse_json::<WhoAmI>(&header, &body)
}

pub fn parse_message(header: &Header, body: &Vec<u8>) -> Result<Message, io::Error> {
    parse_json::<Message>(&header, &body)
}

pub fn parse_feed(header: &Header, body: &Vec<u8>) -> Result<Feed, io::Error> {
    verify_feed_integrity(&String::from_utf8_lossy(&body))?;
    parse_json::<Feed>(&header, &body)
}

pub fn parse_latest(header: &Header, body: &Vec<u8>) -> Result<LatestUserMessage, io::Error> {
    parse_json::<LatestUserMessage>(&header, &body)
}

pub struct ApiClient<R: Read + Unpin, W: Write + Unpin> {
    rpc: RpcClient<R, W>,
}

impl<R: Read + Unpin, W: Write + Unpin> ApiClient<R, W> {
    pub fn new(rpc: RpcClient<R, W>) -> Self {
        Self { rpc }
    }

    pub fn rpc(&mut self) -> &mut RpcClient<R, W> {
        &mut self.rpc
    }

    // whoami: sync
    // Get information about the current ssb-server user.
    pub async fn send_whoami(&mut self) -> Result<RequestNo, io::Error> {
        let args: [&str; 0] = [];
        let req_no = self.rpc.send(&["whoami"], RpcType::Async, &args).await?;
        Ok(req_no)
    }

    // get: async
    // Get a message by its hash-id. (sould start with %)
    pub async fn send_get(&mut self, msg_id: &str) -> Result<RequestNo, io::Error> {
        let req_no = self.rpc.send(&["get"], RpcType::Async, &msg_id).await?;
        Ok(req_no)
    }
    // createHistoryStream: source
    // (hist) Fetch messages from a specific user, ordered by sequence numbers.
    pub async fn send_create_history_stream<'a>(
        &mut self,
        args: &'a CreateHistoryStreamArgs<'a>,
    ) -> Result<RequestNo, io::Error> {
        let req_no = self
            .rpc
            .send(&["createHistoryStream"], RpcType::Source, &args)
            .await?;
        Ok(req_no)
    }

    // createFeedStream: source
    // (feed) Fetch messages ordered by their claimed timestamps.
    pub async fn send_create_feed_stream<'a>(
        &mut self,
        args: &'a CreateStreamArgs<u64>,
    ) -> Result<RequestNo, io::Error> {
        let req_no = self
            .rpc
            .send(&["createFeedStream"], RpcType::Source, &args)
            .await?;
        Ok(req_no)
    }

    // latest: source
    // Get the seq numbers of the latest messages of all users in the database.
    pub async fn send_latest(&mut self) -> Result<RequestNo, io::Error> {
        let args: [&str; 0] = [];
        let req_no = self.rpc.send(&["latest"], RpcType::Source, &args).await?;
        Ok(req_no)
    }
}

pub fn stringify_json(v: &serde_json::Value) -> Result<String, io::Error> {
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