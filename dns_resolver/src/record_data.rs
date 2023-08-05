use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum RecordData {
    A(Ipv4Addr),
    NS(String),
    Other(Vec<u8>),
}
