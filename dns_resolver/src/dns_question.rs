use std::error::Error;

use crate::{class::Class, record_type::RecordType};

#[derive(Debug, Default)]
pub struct DNSQuestion {
    name: Vec<u8>,
    type_: RecordType,
    class: Class,
}

impl DNSQuestion {
    pub fn new(name: Vec<u8>, type_: RecordType, class: Class) -> Self {
        Self { name, type_, class }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.name.clone(),
            (self.type_ as u16).to_be_bytes().to_vec(),
            (self.class as u16).to_be_bytes().to_vec(),
        ]
        .concat()
    }
}

impl TryFrom<(Vec<u8>, &[u8])> for DNSQuestion {
    type Error = Box<dyn Error>;

    fn try_from((name, value): (Vec<u8>, &[u8])) -> Result<Self, Self::Error> {
        Ok(DNSQuestion {
            name,
            type_: u16::from_be_bytes(value[0..2].try_into()?).try_into()?,
            class: u16::from_be_bytes(value[2..4].try_into()?).try_into()?,
        })
    }
}
