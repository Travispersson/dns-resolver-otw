use std::error::Error;

#[derive(Debug, Default)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    pub fn new(id: u16, flags: u16) -> Self {
        Self {
            id,
            flags,
            num_questions: 1,
            ..Default::default()
        }
    }

    pub fn num_questions(&self) -> u16 {
        self.num_questions
    }
    pub fn num_answers(&self) -> u16 {
        self.num_answers
    }
    pub fn num_authorities(&self) -> u16 {
        self.num_authorities
    }
    pub fn num_additionals(&self) -> u16 {
        self.num_additionals
    }
    pub fn to_bytes(&self) -> Vec<u8> {
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
