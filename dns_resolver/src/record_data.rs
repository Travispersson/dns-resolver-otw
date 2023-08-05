use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum RecordData {
    A(Ipv4Addr),
    NS(String),
    Other(Vec<u8>),
}

impl RecordData {
    pub fn get_A(&self) -> Option<&Ipv4Addr> {
        match self {
            RecordData::A(ip) => Some(ip),
            _ => None,
        }
    }
    pub fn get_NS(&self) -> Option<&str> {
        match self {
            RecordData::NS(name) => Some(name),
            _ => None,
        }
    }
    pub fn get_Other(&self) -> Option<&[u8]> {
        match self {
            RecordData::Other(data) => Some(data),
            _ => None,
        }
    }
}
