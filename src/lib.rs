use rand::Rng;

#[derive(Debug)]
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

impl Default for DNSHeader {
    fn default() -> Self {
        DNSHeader {
            id: 0,
            flags: 0,
            num_questions: 0,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        }
    }
}

#[derive(Debug)]
struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl Default for DNSQuestion {
    fn default() -> Self {
        DNSQuestion {
            name: vec![],
            type_: 0,
            class: 0,
        }
    }
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
    const UDP_DNS_RESPONSE_SIZE: usize = 1024;

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
}
