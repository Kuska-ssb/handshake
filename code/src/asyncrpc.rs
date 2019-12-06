use log::debug;

use async_std::io;
use async_std::prelude::*;
use crate::asyncboxstream::{AsyncBoxStreamRead,AsyncBoxStreamWrite};

const RPC_HEADER_STREAM_FLAG : u8 = 1 << 3;
const RPC_HEADER_END_OR_ERROR_FLAG : u8 = 1 << 2;
const RPC_HEADER_BODY_TYPE_MASK : u8 = 0b11;

fn to_ioerr<T: ToString>(err: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[derive(Debug,PartialEq)]
pub enum BodyType {
    Binary,
    UTF8,
    JSON,
}

#[derive(Debug,PartialEq)]
pub enum RpcType {
    Async,
    Source,
}

impl RpcType {
    pub fn rpc_id(&self) -> &'static str {
        match self {
            RpcType::Async => "async",
            RpcType::Source => "source",
        }
    }
}


pub type RequestNo = i32;

#[derive(Debug,PartialEq)]
pub struct Header {
    pub req_no : RequestNo,
    pub is_stream : bool,
    pub is_end_or_error : bool,
    pub body_type : BodyType,
    pub body_len : u32,
}

impl Header {
    pub fn size_encoded() -> usize {
        return 9;
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Header,io::Error> {
        if bytes.len() < Header::size_encoded() {
            return Err(to_ioerr("header size too small"));
        }

        let is_stream = (bytes[0] & RPC_HEADER_STREAM_FLAG) == RPC_HEADER_STREAM_FLAG;
        let is_end_or_error = (bytes[0] & RPC_HEADER_END_OR_ERROR_FLAG) == RPC_HEADER_END_OR_ERROR_FLAG;
        let body_type = match bytes[0] & RPC_HEADER_BODY_TYPE_MASK {
            0 => BodyType::Binary,
            1 => BodyType::UTF8,
            2 => BodyType::JSON,
            _ => return Err(to_ioerr("bad body type")),
        };

        let mut body_len_buff = [0u8;4];
        body_len_buff.copy_from_slice(&bytes[1..5]);
        let body_len = u32::from_be_bytes(body_len_buff);

        let mut reqno_buff = [0u8;4];
        reqno_buff.copy_from_slice(&bytes[5..9]);
        let req_no = i32::from_be_bytes(reqno_buff);

        Ok(Header{
            req_no, is_stream, is_end_or_error, body_type, body_len
        })
    }

    pub fn to_array(&self) -> [u8;9] {        
        let mut flags : u8 = 0;
        if self.is_end_or_error {
            flags |= RPC_HEADER_END_OR_ERROR_FLAG;
        }
        if self.is_stream {
            flags |= RPC_HEADER_STREAM_FLAG;
        }
        flags |= match self.body_type {
            BodyType::Binary => 0,
            BodyType::UTF8   => 1,
            BodyType::JSON   => 2,     
        };
        let len = self.body_len.to_be_bytes();
        let req_no = self.req_no.to_be_bytes();
        
        let mut encoded = [0u8;9];
        encoded[0] = flags;
        encoded[1..5].copy_from_slice(&len[..]);
        encoded[5..9].copy_from_slice(&req_no[..]);
        
        encoded
    }
}

// WhoAmI ---------------------------------------

// https://github.com/ssbc/ssb-db/blob/master/api.md
#[derive(Debug,Serialize)]
pub struct CreateFeedStreamArgs<'a> {
    /// live (boolean, default: false): Keep the stream open and emit new messages as they are received
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live : Option<bool>,
    
    /// gt (greater than), gte (greater than or equal) define the lower bound of the range to be streamed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gt : Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gte : Option<&'a str>,

    /// lt (less than), lte (less than or equal) define the higher bound of the range to be streamed. Only key/value pairs where the key is less than (or equal to) this option will be included in the range. When reverse=true the order will be reversed, but the records streamed will be the same.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lt : Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lte : Option<&'a str>,

    /// reverse (boolean, default: false): a boolean, set true and the stream output will be reversed. Beware that due to the way LevelDB works, a reverse seek will be slower than a forward seek.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse : Option<bool>,

    /// keys (boolean, default: true): whether the data event should contain keys. If set to true and values set to false then data events will simply be keys, rather than objects with a key property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys : Option<bool>,

    /// values (boolean, default: true): whether the data event should contain values. If set to true and keys set to false then data events will simply be values, rather than objects with a value property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values : Option<bool>,

    /// limit (number, default: -1): limit the number of results collected by this stream. This number represents a maximum number of results and may not be reached if you get to the end of the data first. A value of -1 means there is no limit. When reverse=true the highest keys will be returned instead of the lowest keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit : Option<u64>,

    /// fillCache (boolean, default: false): wheather LevelDB's LRU-cache should be filled with data read.
    #[serde(rename = "fillCache")] 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_cache : Option<bool>,
    
    /// keyEncoding / valueEncoding (string): the encoding applied to each read piece of data.
    #[serde(rename = "keyEncoding")] 
    pub key_encoding : &'a str,

    #[serde(rename = "valueEncoding")] 
    pub value_encoding : &'a str,
}

#[derive(Debug,Serialize)]
pub struct CreateHistoryStreamArgs<'a> {
 
    // id (FeedID, required): The id of the feed to fetch.
    pub id : &'a str,

    /// (number, default: 0): If seq > 0, then only stream messages with sequence numbers greater than seq.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq : Option<u64>,  

    /// live (boolean, default: false): Keep the stream open and emit new messages as they are received
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live : Option<bool>,
    
    /// keys (boolean, default: true): whether the data event should contain keys. If set to true and values set to false then data events will simply be keys, rather than objects with a key property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys : Option<bool>,

    /// values (boolean, default: true): whether the data event should contain values. If set to true and keys set to false then data events will simply be values, rather than objects with a value property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values : Option<bool>,

    /// limit (number, default: -1): limit the number of results collected by this stream. This number represents a maximum number of results and may not be reached if you get to the end of the data first. A value of -1 means there is no limit. When reverse=true the highest keys will be returned instead of the lowest keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit : Option<u64>,

}

#[derive(Debug,Deserialize)]
pub struct WhoAmI {
    pub id : String,
}

#[derive(Debug,Deserialize)]
pub struct MessageMention {
    pub link : String,
    pub name : Option<String>,
}

#[derive(Debug,Deserialize)]
pub struct MessageContent {
    #[serde(rename = "type")] 
    pub xtype : String,
    pub text : String,
    pub mentions : Vec<MessageMention>,
}

#[derive(Debug,Deserialize)]
pub struct Message {
    pub previous : String,
    pub author : String,
    pub sequence : u64,
    pub timestamp : u64,
    pub hash : String,
    pub content : MessageContent,
    pub signature : String,
}

#[derive(Debug,Deserialize)]
struct ErrorRes {
    pub name : String,
    pub message : String,
    pub stack : String,
}

pub struct Client<R : io::Read + Unpin, W : io::Write + Unpin> {
    box_reader : AsyncBoxStreamRead<R>,
    box_writer : AsyncBoxStreamWrite<W>,
    req_no : RequestNo,
}


fn parse_json<'a,T:serde::Deserialize<'a>>(header: &'a Header, body : &'a Vec<u8>) -> Result<T,io::Error> {
    if header.is_end_or_error {
        let error : ErrorRes = serde_json::from_slice(&body[..]).map_err(to_ioerr)?;
        Err(to_ioerr(format!("{:?}",error)))
    } else {
        let res : T = serde_json::from_slice(&body[..]).map_err(to_ioerr)?;
        Ok(res)
    }
}

impl<R:io::Read+Unpin , W:io::Write+Unpin> Client<R,W> {

    pub fn new(box_reader :AsyncBoxStreamRead<R>, box_writer :AsyncBoxStreamWrite<W>) -> Client<R,W> {
        Client { box_reader, box_writer, req_no : 1 }
    }

    pub async fn recv(&mut self) -> Result<(Header,Vec<u8>),io::Error> {

        let mut rpc_header_raw = [0u8;9];
        self.box_reader.read_exact(&mut rpc_header_raw[..]).await?;
        let rpc_header = Header::from_slice(&rpc_header_raw[..])?;

        let mut rpc_body : Vec<u8> = vec![0;rpc_header.body_len as usize];
        self.box_reader.read_exact(&mut rpc_body[..]).await?;

        Ok((rpc_header,rpc_body))
    }

    async fn send<T:serde::Serialize>(&mut self, req_no : RequestNo, name : &[&str], rpc_type: RpcType, args :&T) -> Result<RequestNo,io::Error>{

        let mut body = String::from("{\"name\":");
        body.push_str(&serde_json::to_string(&name).map_err(to_ioerr)?);
        body.push_str(",\"type\":\"");
        body.push_str(rpc_type.rpc_id());
        body.push_str("\",\"args\":[");
        body.push_str(&serde_json::to_string(&args).map_err(to_ioerr)?);
        body.push_str("]}");

        let rpc_header = Header {
            req_no,
            is_stream : rpc_type == RpcType::Source,
            is_end_or_error : false,
            body_type : BodyType::JSON,
            body_len : body.len() as u32,
        }.to_array();

        self.box_writer.write_all(&rpc_header[..]).await?;
        self.box_writer.write_all(body.as_bytes()).await?;

        Ok(self.req_no)
    }

    pub async fn send_cancel_stream(&mut self, req_no: RequestNo) -> Result<(),io::Error> {
        let body_bytes = b"true";
        
        let rpc_header = Header {
            req_no,
            is_stream : true,
            is_end_or_error : true,
            body_type : BodyType::JSON,
            body_len : body_bytes.len() as u32,
        }.to_array();

        self.box_writer.write_all(&rpc_header[..]).await?;
        self.box_writer.write_all(&body_bytes[..]).await
    }

    pub async fn close(&mut self) -> Result<(),io::Error> {
        self.box_writer.close().await
    }

    // whoami: sync
    // Get information about the current ssb-server user.
    pub async fn send_whoami(&mut self) -> Result<RequestNo,io::Error> {
        self.req_no += 1;
        let args : [&str;0] = [];         
        self.send(self.req_no,&["whoami"],RpcType::Async,&args).await?;
        self.box_writer.flush().await?;

        Ok(self.req_no)
    }
    pub fn parse_whoami(&self, header: &Header, body: &Vec<u8>) -> Result<WhoAmI,io::Error> {
        parse_json::<WhoAmI>(&header,&body)
    }

    // get: async
    // Get a message by its hash-id. (sould start with %)
    pub async fn send_get(&mut self, msg_id : &str) -> Result<RequestNo,io::Error> {
        self.req_no += 1;
        let args : [&str;1] = [ msg_id ];         
        self.send(self.req_no,&["get"],RpcType::Async,&args).await?;
        self.box_writer.flush().await?;

        Ok(self.req_no)
    }
    pub fn parse_get(&self, header: &Header, body: &Vec<u8>) -> Result<Message,io::Error> {
        parse_json::<Message>(&header,&body)
    }
    
    // createFeedStream: source
    // (feed) Fetch messages ordered by their claimed timestamps.
    pub async fn send_create_history_stream<'a>(&mut self, args : &'a CreateHistoryStreamArgs<'a>) -> Result<RequestNo,io::Error> {
        self.req_no += 1;
        self.send(self.req_no,&["createHistoryStream"],RpcType::Source,&args).await?;
        self.box_writer.flush().await?;

        Ok(self.req_no)
    }
}

mod test {
    use super::{Header,BodyType};

    #[test]
    fn test_header_encoding_1() {
        let h = Header::from_slice(&(Header{
            req_no : 5,
            is_stream : true,
            is_end_or_error : false,
            body_type : BodyType::JSON,
            body_len : 123,
        }.to_array())[..]).unwrap();
        assert_eq!(h.req_no,5);
        assert_eq!(h.is_stream, true);
        assert_eq!(h.is_end_or_error, false);
        assert_eq!(h.body_type, BodyType::JSON);
        assert_eq!(h.body_len, 123);
    }

    #[test]
    fn test_header_encoding_2() {
        let h = Header::from_slice(&(Header{
            req_no : -5,
            is_stream : false,
            is_end_or_error : true,
            body_type : BodyType::Binary,
            body_len : 2123,
        }.to_array())[..]).unwrap();
        assert_eq!(h.req_no,-5);
        assert_eq!(h.is_stream, false);
        assert_eq!(h.is_end_or_error, true);
        assert_eq!(h.body_type, BodyType::Binary);
        assert_eq!(h.body_len, 2123);
    }
}