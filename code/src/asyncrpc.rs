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

pub enum RpcType {
    Async,
    Source,
}

impl RpcType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Async => "async",
            Source => "source",
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


fn parse<'a,T:serde::Deserialize<'a>>(header: &'a Header, body : &'a Vec<u8>) -> Result<T,io::Error> {
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

    async fn send<T:serde::Serialize>(&mut self, req_no : RequestNo, name : &[&str], rpc_type: RpcType, args :&T) -> Result<RequestNo,io::Error>{
        let mut body = String::from("{\"name\":");
        body.push_str(&serde_json::to_string(&name).map_err(to_ioerr)?);
        body.push_str(",\"type\":\"");
        body.push_str(rpc_type.as_str());
        body.push_str("\",\"args\":");
        body.push_str(&serde_json::to_string(&args).map_err(to_ioerr)?);
        body.push_str("}");

        debug!("RPC {}",body);

        let rpc_header = Header {
            req_no,
            is_stream : false,
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
        parse::<WhoAmI>(&header,&body)
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
        parse::<Message>(&header,&body)
    }
    
    pub async fn recv(&mut self) -> Result<(Header,Vec<u8>),io::Error> {

        let mut rpc_header_raw = [0u8;9];
        self.box_reader.read_exact(&mut rpc_header_raw[..]).await?;
        let rpc_header = Header::from_slice(&rpc_header_raw[..])?;

        let mut rpc_body : Vec<u8> = vec![0;rpc_header.body_len as usize];
        self.box_reader.read_exact(&mut rpc_body[..]).await?;

        Ok((rpc_header,rpc_body))
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