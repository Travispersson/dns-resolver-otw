use std::{error::Error, net::Ipv4Addr};

use crate::{constants, decode_name, record_data::RecordData, record_type::RecordType};

#[derive(Debug)]
pub struct DNSRecord {
    name: Vec<u8>,
    type_: RecordType,
    class: u16,
    ttl: u32,
    data: RecordData,
}

impl DNSRecord {
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    pub fn type_(&self) -> RecordType {
        self.type_
    }
    pub fn class(&self) -> u16 {
        self.class
    }
    pub fn ttl(&self) -> u32 {
        self.ttl
    }
    pub fn data(&self) -> &RecordData {
        &self.data
    }

    pub fn parse((data, cursor): (&[u8], usize)) -> Result<(Self, usize), Box<dyn Error>> {
        let mut current_pos = cursor;

        let (name, current) = decode_name(data, current_pos)?;
        current_pos += current;

        let type_ = u16::from_be_bytes(data[current_pos..current_pos + 2].try_into()?);
        let class = u16::from_be_bytes(data[current_pos + 2..current_pos + 4].try_into()?);
        let ttl = u32::from_be_bytes(data[current_pos + 4..current_pos + 8].try_into()?);
        let data_length = u16::from_be_bytes(data[current_pos + 8..current_pos + 10].try_into()?);
        current_pos += constants::DNS_RECORD_SIZE;

        let data = match type_.try_into() {
            Ok(RecordType::A) => {
                let [a, b, c, d] = data[current_pos..current_pos+4] else {
                    panic!("Expected a valid IPv4 address");
                };
                current_pos += 4;
                RecordData::A(Ipv4Addr::new(a, b, c, d))
            }
            Ok(RecordType::NS) | Ok(RecordType::CNAME) => {
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
                type_: type_.try_into()?,
                class,
                ttl,
                data,
            },
            current_pos - cursor,
        ))
    }
}
