use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error, PartialEq)]
pub enum AppError {
    #[error("dberror: {0}")]
    DbError(String),
}
