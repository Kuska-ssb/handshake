use std::cmp; 
use std::borrow::Cow;
use std::io::{Read,Write,self};

#[derive(Debug)]
pub struct CircularBuffer {
    buffer: Box<[u8]>,
    start: usize, 
    end:   usize,
    len:   usize,
}

impl CircularBuffer {
    pub fn new(capacity : usize) -> CircularBuffer {
        CircularBuffer {
            buffer: vec![0; capacity].into_boxed_slice(),
            start: 0,
            end: 0,
            len: 0,
        }
    }
    pub fn to_string(&self) -> Cow<str> {
        if self.len == 0 {
            Cow::Borrowed("")
        } else {
            let mut s = String::new();
            if self.start < self.end {
                s.push_str(&hex::encode(&self.buffer[self.start..self.end]));    
            } else {
                s.push_str(&hex::encode(&self.buffer[self.start..]));    
                s.push_str(&hex::encode(&self.buffer[..self.end]));
            }
            Cow::Owned(s)
        }
    }
    
    pub fn len(&self) -> usize {
        return self.len;
    }
    pub fn cap(&self) -> usize {
        return self.buffer.len();
    }

    pub fn write_passthrough<R: Read>(&mut self, reader : &mut R) -> io::Result<usize> {
        
        if self.len == self.buffer.len() {
            Ok(0)
        } else {
            if self.start <= self.end {
                // write at %end -> end_buffer 
                let len = reader.read(&mut self.buffer[self.end..])?;
                self.end = (len + self.end) % self.buffer.len();
                Ok(len)
            } else {
                // write at %end -> %start
                let len = reader.read(&mut self.buffer[self.end..self.start])?;
                self.end += self.end;
                Ok(len)
            }
        }
    } 

}

impl Read for CircularBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len()==0 || self.buffer.len() == 0 {
            Ok(0)
        } else {
            let last_len = self.len;

            // read from the %start to the %end or end of buffer
            let len_a = cmp::min(buf.len(),cmp::max(self.buffer.len(),self.end)-self.start);
            buf[..len_a].copy_from_slice(&self.buffer[self.start..self.start+len_a]);
            self.start = (self.start + len_a) % self.buffer.len();
            self.len -= len_a;

            // if there's somthing pending to read, the head is at the beginning
            if self.len > 0 && buf.len() > len_a {
                let len_b = cmp::min(buf.len()-len_a,self.end);
                buf[len_a..len_a+len_b].copy_from_slice(&self.buffer[..len_b]);
                self.start += len_b;
                self.len -= len_b;
            }  

            Ok(last_len - self.len)
        }
    }
}

impl Write for CircularBuffer {

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {

        if buf.len()==0 || self.len == self.buffer.len() {
            Ok(0)
        } else {        
            let last_len = self.len;
            let mut offset = 0;

            if self.start <= self.end {
                // append after the %end, up to (maximum) the end of the buffer
                // if end of buffer is reached, %end points to the start of the buffer
                let len = cmp::min(self.buffer.len()-self.end,buf.len());
                self.buffer[self.end..self.end+len].copy_from_slice(&buf[..len]);
                self.end = (len + self.end) % self.buffer.len();
                self.len += len;
                offset = len;
            }
            
            if offset < buf.len() {
                // append from the %end to the %start   
                let len = cmp::min(self.start-self.end,buf.len()-offset);        
                self.buffer[self.end..self.end+len].copy_from_slice(&buf[offset..offset+len]);
                self.end += len;
                self.len += len;
            }

            Ok(self.len - last_len)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

mod test {
    use super::*;

    #[test]
    fn check() -> io::Result<()> {
        let mut b = super::CircularBuffer::new(6);
        assert_eq!("",b.to_string());

        // add 
        assert_eq!(5,b.write(&[1,2,3,4,5])?);
        assert_eq!("0102030405", b.to_string());
        assert_eq!("010203040500", hex::encode(&b.buffer));

        // add with overflow
        assert_eq!(1,b.write(&[6,7,8])?);
        assert_eq!("010203040506",b.to_string());
        assert_eq!("010203040506", hex::encode(&b.buffer));

        // get 4
        let mut buff = [0u8;4];
        assert_eq!(4,b.read(&mut buff[..])?);
        assert_eq!("0506",b.to_string());
        assert_eq!("01020304",hex::encode(&buff[..]));
        assert_eq!("010203040506", hex::encode(&b.buffer));

        // add 2
        assert_eq!(2,b.write(&[7,8])?);
        assert_eq!("05060708",b.to_string());
        assert_eq!("070803040506",hex::encode(&b.buffer[..]));
        
        // remove 3
        let mut buff = [0u8;3];
        assert_eq!(3,b.read(&mut buff[..])?);
        assert_eq!("08",b.to_string());
        assert_eq!("050607",hex::encode(&buff[..]));
        assert_eq!("070803040506",hex::encode(&b.buffer[..]));
        
        // add 5
        assert_eq!(5,b.write(&[9,10,11,12,13,14,15,16])?);
        assert_eq!("08090a0b0c0d",b.to_string());
        assert_eq!("0d08090a0b0c",hex::encode(&b.buffer[..]));

        // get 6
       let mut buff = [0u8;6];
       assert_eq!(6,b.read(&mut buff[..])?);
       assert_eq!("",b.to_string());
       assert_eq!("08090a0b0c0d",hex::encode(&buff[..]));
       assert_eq!("0d08090a0b0c",hex::encode(&b.buffer[..]));
        
       Ok(())
    }
}
