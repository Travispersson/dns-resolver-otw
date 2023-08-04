use std::{
    error::Error,
    net::{Ipv4Addr, UdpSocket},
};

use rand::Rng;

mod constants {
    pub const UDP_DNS_RESPONSE_SIZE: usize = 1024;
    pub const DNS_HEADER_SIZE: usize = 12;
    pub const DNS_QUESTION_SIZE: usize = 4;
    pub const DNS_RECORD_SIZE: usize = 10;
    pub const CLASS_IN: u16 = 1;
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    pub const RECURSION_DESIRED: u16 = 1 << 8;
    pub const AUTHORITATIVE_NAMESERVER: u16 = 0;
}
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
            type_: u16::from_be_bytes(value[0..2].try_into()?),
            class: u16::from_be_bytes(value[2..4].try_into()?),
        })
    }
}

fn decode_name(data: &[u8], cursor: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut current_pos: usize = cursor;
    let mut parts = vec![];
    let mut length = data[current_pos];

    while length != 0 {
        if length & 0b11000000 != 0 {
            parts.push(decode_compressed_name(data, current_pos)?.0);
            current_pos += 2;
            return Ok((parts.join("."), current_pos - cursor));
        } else {
            let start = current_pos + 1;
            let end = current_pos + length as usize + 1;
            parts.push(String::from_utf8(data[start..end].to_vec()).unwrap());
            current_pos += length as usize + 1;
            length = data[current_pos];
        }
    }
    current_pos += 1; // For the 0 at the end.

    Ok((parts.join("."), current_pos - cursor))
}

fn decode_compressed_name(buf: &[u8], cursor: usize) -> Result<(String, usize), Box<dyn Error>> {
    // takes the bottom 6 bits of the length byte, plus the next byte, and converts that to an integer called pointer
    // saves our current position in reader
    let parts = [buf[cursor] & 0b00111111, buf[cursor + 1]];
    let pointer = u16::from_be_bytes(parts) as usize;

    decode_name(buf, pointer)
}

fn encode_dns_name(domain_name: &str) -> Vec<u8> {
    let mut bytes = domain_name
        // Split domain name on .
        .split('.')
        // Map each label to a length-prefixed byte array
        .fold(vec![], |mut acc, label| {
            acc.push(label.len() as u8);
            acc.extend_from_slice(label.as_bytes());
            acc
        });
    // Add a 0 byte to terminate the name
    bytes.push(0);

    bytes
}

#[derive(Debug)]
enum RecordData {
    A(Ipv4Addr),
    NS(String),
    Other(Vec<u8>),
}

#[derive(Debug)]
struct DNSRecord {
    name: Vec<u8>,
    type_: RecordType,
    class: u16,
    ttl: u32,
    data: RecordData,
}

impl DNSRecord {
    fn parse((data, cursor): (&[u8], usize)) -> Result<(Self, usize), Box<dyn Error>> {
        let mut current_pos = cursor;

        let (name, current) = decode_name(data, current_pos)?;
        current_pos += current;

        let type_ = u16::from_be_bytes(data[current_pos..current_pos + 2].try_into()?);
        let class = u16::from_be_bytes(data[current_pos + 2..current_pos + 4].try_into()?);
        let ttl = u32::from_be_bytes(data[current_pos + 4..current_pos + 8].try_into()?);
        let data_length = u16::from_be_bytes(data[current_pos + 8..current_pos + 10].try_into()?);
        current_pos += constants::DNS_RECORD_SIZE;

        let data = match type_.into() {
            RecordType::A => {
                let [a, b, c, d] = data[current_pos..current_pos+4] else {
                    panic!("Expected a valid IPv4 address");
                };
                current_pos += 4;
                RecordData::A(Ipv4Addr::new(a, b, c, d))
            }
            RecordType::NS => {
                let (name, current) = decode_name(data, current_pos)?;
                current_pos += current;
                RecordData::NS(name)
            }
            _ => {
                let (start, end) = (current_pos, current_pos + data_length as usize);
                let read_data = data[start..end].to_vec();
                current_pos += data_length as usize;
                RecordData::Other(read_data)
            }
        };

        Ok((
            DNSRecord {
                name: name.into_bytes().to_vec(),
                type_: type_.into(),
                class,
                ttl,
                data,
            },
            current_pos - cursor,
        ))
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u16)]
enum RecordType {
    // Bunch more can be found here.. https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
    A = 1,
    NS = 2,
    NotImplemented,
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            _ => RecordType::NotImplemented,
        }
    }
}

fn build_query(domain_name: &str, record_type: RecordType, flags: u16) -> Vec<u8> {
    let id = rand::thread_rng().gen_range(0..=std::u16::MAX);
    let header = DNSHeader {
        id,
        flags,
        num_questions: 1,
        num_additionals: 0,
        num_authorities: 0,
        num_answers: 0,
    };

    let question = DNSQuestion {
        name: encode_dns_name(domain_name),
        type_: record_type as u16,
        class: constants::CLASS_IN,
    };

    let mut bytes = header.to_bytes();
    bytes.extend(question.to_bytes());

    bytes
}
#[derive(Debug)]
struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    fn parse(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        DNSPacket::try_from(data)
    }
}

impl TryFrom<&[u8]> for DNSPacket {
    type Error = Box<dyn Error>;

    fn try_from(packet: &[u8]) -> Result<Self, Self::Error> {
        let header = DNSHeader::try_from(&packet[0..constants::DNS_HEADER_SIZE])?;
        let mut current_pos = constants::DNS_HEADER_SIZE;

        let mut questions = vec![];
        for _ in 0..header.num_questions {
            let question = {
                let (name, current) = decode_name(packet, current_pos)?;
                current_pos += current;
                DNSQuestion::try_from((
                    name.into_bytes().to_vec(),
                    &packet[current_pos..current_pos + constants::DNS_QUESTION_SIZE],
                ))?
            };
            current_pos += constants::DNS_QUESTION_SIZE;
            questions.push(question);
        }

        let mut answers = vec![];
        for _ in 0..header.num_answers {
            let (record, cursor) = DNSRecord::parse((packet, current_pos))?;
            current_pos += cursor;
            answers.push(record);
        }

        let mut authorities = vec![];
        for _ in 0..header.num_authorities {
            let (record, cursor) = DNSRecord::parse((packet, current_pos))?;
            current_pos += cursor;
            authorities.push(record);
        }

        let mut additionals = vec![];
        for _ in 0..header.num_additionals {
            let (record, cursor) = DNSRecord::parse((packet, current_pos))?;
            current_pos += cursor;
            additionals.push(record);
        }

        Ok(DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

fn send_query(
    ip: Ipv4Addr,
    domain_name: &str,
    record_type: RecordType,
) -> Result<DNSPacket, Box<dyn Error>> {
    let query = build_query(
        domain_name,
        record_type,
        constants::AUTHORITATIVE_NAMESERVER,
    );

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("Couldn't bind to address");
    socket
        .send_to(&query, (ip, 53))
        .expect("Something went wrong...");

    let mut response_buffer = [0; constants::UDP_DNS_RESPONSE_SIZE];
    socket
        .recv_from(&mut response_buffer)
        .expect("Expecected a response");

    DNSPacket::try_from(&response_buffer[..])
}

fn get_answer(packet: &DNSPacket) -> Option<&DNSRecord> {
    //return the first Record Type A Packet in the Answer section
    packet
        .answers
        .iter()
        .find(|record| matches!(&record.data, RecordData::A(_)))
}

fn get_name_server_ip(packet: &DNSPacket) -> Option<&Ipv4Addr> {
    //return the first A record in the Additional section
    packet
        .additionals
        .iter()
        .find(|record| matches!(&record.data, RecordData::A(_)))
        .map(|record| match record.data {
            RecordData::A(ref ip) => ip,
            _ => panic!("Expected A record"),
        })
}

fn get_name_server(packet: &DNSPacket) -> Option<&str> {
    //return the first NS record in the Authority section
    packet
        .authorities
        .iter()
        .find(|record| matches!(&record.data, RecordData::NS(_)))
        .map(|record| match record.data {
            RecordData::NS(ref name) => name.as_str(),
            _ => panic!("Expected NS record"),
        })
}

fn resolve(domain_name: &str, record_type: RecordType) -> Result<Ipv4Addr, Box<dyn Error>> {
    let mut name_server_ip = Ipv4Addr::new(198, 41, 0, 4);

    loop {
        println!("Resolving {} from {}", domain_name, name_server_ip);
        let packet = send_query(name_server_ip, domain_name, record_type)?;

        if let Some(answer) = get_answer(&packet) {
            let ip = match answer.data {
                RecordData::A(ip) => ip,
                _ => panic!("Expected type A record!"),
            };
            return Ok(ip);
        }

        if let Some(ip) = get_name_server_ip(&packet) {
            name_server_ip = *ip;
        } else {
            let Some(ns_domain) = get_name_server(&packet) else {
                panic!("Expected packet");
            };
            name_server_ip = resolve(ns_domain, RecordType::A)?;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encode() {
        let name = "google.com";
        let expected: Vec<u8> = vec![6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0];
        let result = encode_dns_name(name);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_send_query() {
        let query = send_query(Ipv4Addr::new(198, 41, 0, 4), "google.com", RecordType::A);
        println!("Packet: {:?}", query.unwrap().authorities);
    }

    #[test]
    fn test_resolve() {
        let result = resolve("www.twitter.com", RecordType::A);
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_decode_name() {
        let mut data = [0; constants::UDP_DNS_RESPONSE_SIZE];
        let mut index = 0;
        for p in "www.google.com".split('.') {
            data[index] = p.len() as u8;
            index += 1;
            for c in p.chars() {
                data[index] = c as u8;
                index += 1;
            }
        }

        let decoded_name = decode_name(&data[..], 0).unwrap();
        assert_eq!(decoded_name.0, "www.google.com");
    }
}
