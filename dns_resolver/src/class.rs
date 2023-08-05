use std::error::Error;

#[derive(Debug, Copy, Clone, Default)]
#[repr(u16)]
pub enum Class {
    #[default]
    In = 1,
}

impl TryFrom<u16> for Class {
    type Error = Box<dyn Error>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let class = match value {
            1 => Class::In,
            _ => {
                return Err(format!("Unknown class type: {}", value).into());
            }
        };

        Ok(class)
    }
}
