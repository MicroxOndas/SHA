use thiserror::Error;

#[derive(Error,Debug)]
#[allow(dead_code)]
pub enum ShaError {
    #[error("Invalid algorithm")]
    InvalidAlgorithm,
    #[error("Invalid padding")]
    InvalidPadding,
    #[error("Invalid initial values")]
    InvalidInitialValues,
    #[error("Invalid constants")]
    InvalidConstants,
    #[error("Invalid result")]
    InvalidResult,
    #[error("Error")]
    CustomError(String),
}