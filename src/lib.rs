use std::{error::Error, io::Cursor};

use rand::Rng;

#[derive(Debug, Default)]
struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    fn to_bytes(&self) -> Vec<u8> {
        [
            self.id.to_be_bytes(),
            self.flags.to_be_bytes(),
            self.num_questions.to_be_bytes(),
            self.num_answers.to_be_bytes(),
            self.num_authorities.to_be_bytes(),
            self.num_additionals.to_be_bytes(),
        ]
        .concat()
    }
}

impl TryFrom<&[u8]> for DNSHeader {
    type Error = Box<dyn Error>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // Each of the 6 fields is a 2-byte integer, so there are 12 bytes in all to read.
        Ok(DNSHeader {
            id: u16::from_be_bytes(value[0..2].try_into()?),
            flags: u16::from_be_bytes(value[2..4].try_into()?),
            num_questions: u16::from_be_bytes(value[4..6].try_into()?),
            num_answers: u16::from_be_bytes(value[6..8].try_into()?),
            num_authorities: u16::from_be_bytes(value[8..10].try_into()?),
            num_additionals: u16::from_be_bytes(value[10..12].try_into()?),
        })
    }
}

#[derive(Debug, Default)]
struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl DNSQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        [
            self.name.clone(),
            self.type_.to_be_bytes().to_vec(),
            self.class.to_be_bytes().to_vec(),
        ]
        .concat()
    }
}

impl TryFrom<(Vec<u8>, &[u8])> for DNSQuestion {
    type Error = Box<dyn Error>;

    fn try_from((name, value): (Vec<u8>, &[u8])) -> Result<Self, Self::Error> {
        Ok(DNSQuestion {
            name,
            type_: u16::from_be_bytes(value[2..4].try_into()?),
            class: u16::from_be_bytes(value[4..6].try_into()?),
        })
    }
}

const UDP_DNS_RESPONSE_SIZE: usize = 1024;

fn decode_name(
    reader: &mut Cursor<&[u8; UDP_DNS_RESPONSE_SIZE]>,
) -> Result<String, Box<dyn Error>> {
    let mut length = reader.get_ref()[reader.position() as usize];
    let mut decompressed_names: Vec<String> = vec![];

    let mut current_pos = reader.position();
    while length != 0 {
        // check that first 2 bits are 1
        if length & 0b11000000 != 0 {
            let decoded_name = decode_compressed_name(reader)?;
            decompressed_names.push(decoded_name);
            current_pos += 2;
            reader.set_position(current_pos);
            return Ok(decompressed_names.join("."));
        } else {
            let start = (current_pos + 1) as usize;
            let end = ((current_pos + length as u64) + 1) as usize;
            let buf = reader.get_ref()[start..end].to_vec();
            decompressed_names.push(String::from_utf8(buf)?);
            current_pos += length as u64 + 1;
            length = reader.get_ref()[current_pos as usize];
        }
    }

    reader.set_position(current_pos + 1);
    Ok(decompressed_names.join("."))
}

fn decode_compressed_name(
    reader: &mut Cursor<&[u8; UDP_DNS_RESPONSE_SIZE]>,
) -> Result<String, Box<dyn Error>> {
    // takes the bottom 6 bits of the length byte, plus the next byte, and converts that to an integer called pointer
    // saves our current position in reader
    let pos = reader.position() as usize;
    let parts = [
        reader.get_ref()[pos] & 0b00111111,
        reader.get_ref()[pos + 1],
    ];
    let pointer = u16::from_be_bytes(parts);
    reader.set_position(pointer as u64);
    decode_name(reader)
}

fn encode_dns_name(domain_name: &str) -> Vec<u8> {
    domain_name
        // Split domain name on .
        .split('.')
        // Map each label to a length-prefixed byte array
        .fold(vec![], |mut acc, label| {
            acc.push(label.len() as u8);
            acc.extend_from_slice(label.as_bytes());
            acc
        })
}

#[repr(u16)]
enum RecordType {
    A,
    // Bunch more can be found here.. https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
}

const CLASS_IN: u16 = 1;
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
const RECURSION_DESIRED: u16 = 1 << 8;

fn build_query(domain_name: &str, record_type: RecordType) -> Vec<u8> {
    let encoded = encode_dns_name(domain_name);
    let id = rand::thread_rng().gen_range(0..=std::u16::MAX);
    let header = DNSHeader {
        id,
        flags: RECURSION_DESIRED,
        num_questions: 1,
        ..Default::default()
    };

    let question = DNSQuestion {
        name: encoded,
        type_: record_type as u16,
        class: CLASS_IN,
    };

    let mut bytes = header.to_bytes();
    bytes.extend(question.to_bytes());

    bytes
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        net::{Ipv4Addr, UdpSocket},
    };

    use super::*;

    #[test]
    fn test_encode() {
        let name = "google.com";
        let expected: Vec<u8> = vec![6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109];
        let result = encode_dns_name(name);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_our_code_1_5() {
        let query = build_query("www.example.com", RecordType::A);
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't bind to address");
        socket
            .send_to(&query, "8.8.8.8:53")
            .expect("couldn't reach googles DNS resolver");

        let mut response_buffer = [0; UDP_DNS_RESPONSE_SIZE];
        socket
            .recv_from(&mut response_buffer)
            .expect("Expecected a response");

        // lets verify that some data exist in buffer for now with some shitty test haha
        assert_ne!(response_buffer[0], 0);
    }

    #[test]
    fn test_decode_name() {
        let mut data = [0; UDP_DNS_RESPONSE_SIZE];
        let mut index = 0;
        for p in "www.google.com".split('.') {
            data[index] = p.len() as u8;
            index += 1;
            for c in p.chars() {
                data[index] = c as u8;
                index += 1;
            }
        }

        let mut reader = Cursor::new(&data);
        let decoded_name = decode_name(&mut reader).unwrap();
        assert_eq!(decoded_name, "www.google.com");
    }
}
