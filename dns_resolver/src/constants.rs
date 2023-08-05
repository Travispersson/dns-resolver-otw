pub const UDP_DNS_RESPONSE_SIZE: usize = 1024;
pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_QUESTION_SIZE: usize = 4;
pub const DNS_RECORD_SIZE: usize = 10;
// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const RECURSION_DESIRED: u16 = 1 << 8;
pub const AUTHORITATIVE_NAMESERVER: u16 = 0;
