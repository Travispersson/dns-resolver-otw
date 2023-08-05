use crate::{
    constants, decode_name, dns_header::DNSHeader, dns_question::DNSQuestion, dns_record::DNSRecord,
};
use std::error::Error;

#[derive(Debug)]
pub struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn header(&self) -> &DNSHeader {
        &self.header
    }
    pub fn questions(&self) -> &[DNSQuestion] {
        &self.questions
    }
    pub fn answers(&self) -> &[DNSRecord] {
        &self.answers
    }
    pub fn authorities(&self) -> &[DNSRecord] {
        &self.authorities
    }
    pub fn additionals(&self) -> &[DNSRecord] {
        &self.additionals
    }

    pub fn parse(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        DNSPacket::try_from(data)
    }
}

impl TryFrom<&[u8]> for DNSPacket {
    type Error = Box<dyn Error>;

    fn try_from(packet: &[u8]) -> Result<Self, Self::Error> {
        let header = DNSHeader::try_from(&packet[0..constants::DNS_HEADER_SIZE])?;
        let mut current_pos = constants::DNS_HEADER_SIZE;

        let mut questions = vec![];
        for _ in 0..header.num_questions() {
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
        for _ in 0..header.num_answers() {
            let (record, cursor) = DNSRecord::parse((packet, current_pos))?;
            current_pos += cursor;
            answers.push(record);
        }

        let mut authorities = vec![];
        for _ in 0..header.num_authorities() {
            let (record, cursor) = DNSRecord::parse((packet, current_pos))?;
            current_pos += cursor;
            authorities.push(record);
        }

        let mut additionals = vec![];
        for _ in 0..header.num_additionals() {
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
