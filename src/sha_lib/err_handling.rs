
#[derive(Debug)]
#[allow(dead_code)]
pub enum ShaError {
    InvalidAlgorithm,
    InvalidPadding,
    InvalidInitialValues,
    InvalidConstants,
    InvalidResult,
    CustomError(String),
}

