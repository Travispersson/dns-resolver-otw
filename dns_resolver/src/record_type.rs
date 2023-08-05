use std::error::Error;

#[derive(Debug, Copy, Clone, Default)]
#[repr(u16)]
pub enum RecordType {
    // Bunch more can be found here.. https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
    #[default]
    A = 1,
    NS = 2,
    CNAME = 5,
    NotImplemented,
}

impl TryFrom<u16> for RecordType {
    type Error = Box<dyn Error>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let record = match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            _ => RecordType::NotImplemented,
        };

        Ok(record)
    }
}
