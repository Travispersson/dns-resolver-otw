use std::{
    error::Error,
    net::{Ipv4Addr, UdpSocket},
};

use class::Class;
use dns_header::DNSHeader;
use dns_packet::DNSPacket;
use dns_question::DNSQuestion;
use dns_record::DNSRecord;
use rand::Rng;
use record_data::RecordData;
use record_type::RecordType;

pub mod constants;
pub mod record_type;
pub mod dns_question;
pub mod dns_header;
pub mod class;
pub mod record_data;
pub mod dns_record;
pub mod dns_packet;


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
    current_pos += 1;

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



fn build_query(domain_name: &str, record_type: RecordType, flags: u16) -> Vec<u8> {
    let id = rand::thread_rng().gen_range(0..=std::u16::MAX);
    let header = DNSHeader::new(id, flags);

    let question = DNSQuestion::new(encode_dns_name(domain_name), record_type, Class::In);

    let mut bytes = header.to_bytes();
    bytes.extend(question.to_bytes());

    bytes
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
        .answers()
        .iter()
        .find(|record| matches!(&record.data(), RecordData::A(_)))
}

fn get_name_server_ip(packet: &DNSPacket) -> Option<&Ipv4Addr> {
    //return the first A record in the Additional section
    packet
        .additionals()
        .iter()
        .find(|record| matches!(&record.data(), RecordData::A(_)))
        .map(|record| match record.data() {
            RecordData::A(ref ip) => ip,
            _ => panic!("Expected A record"),
        })
}

fn get_name_server(packet: &DNSPacket) -> Option<&str> {
    //return the first NS record in the Authority section
    packet
        .authorities()
        .iter()
        .find(|record| matches!(&record.data(), RecordData::NS(_)))
        .map(|record| match record.data() {
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
            let ip = match answer.data() {
                RecordData::A(ip) => ip,
                _ => panic!("Expected type A record!"),
            };
            return Ok(*ip);
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
