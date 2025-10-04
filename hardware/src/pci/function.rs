#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    num_derive::ToPrimitive,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[repr(transparent)]
pub struct Function(u8);

impl Function {
    #[allow(dead_code)]
    const MAX: u8 = 0b111;
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPciFunction {
    #[error("Function maximum is 3 bits (0-7): {0} is too large")]
    TooLarge(u8),
}

impl std::fmt::LowerHex for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:01x}", self.0)
    }
}

impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:01x}", self)
    }
}

impl TryFrom<u8> for Function {
    type Error = InvalidPciFunction;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 7 {
            Err(InvalidPciFunction::TooLarge(value))
        } else {
            Ok(Function(value))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FunctionParseError {
    #[error("Invalid pci function syntax: {0}")]
    InvalidSyntax(String),
    #[error(transparent)]
    InvalidFunction(InvalidPciFunction),
}

impl TryFrom<&str> for Function {
    type Error = FunctionParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 1 {
            let value = u8::from_str_radix(value, 16).map_err(|_| {
                FunctionParseError::InvalidSyntax(format!(
                    "{} is illegal; should be a single digit between 0 and 7",
                    value
                ))
            })?;
            Function::try_from(value).map_err(FunctionParseError::InvalidFunction)
        } else {
            Err(FunctionParseError::InvalidSyntax(format!(
                "length for pci function: {} is illegal; should be a single digit between 0 and 7",
                value
            )))
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::pci::function::Function;

    impl bolero::TypeGenerator for Function {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(
                Function::try_from(driver.produce::<u8>()? & Self::MAX)
                    .unwrap_or_else(|_| unreachable!()),
            )
        }
    }
}
