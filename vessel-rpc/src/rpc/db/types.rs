use rst_common::with_errors::thiserror::{self, Error};

#[derive(Error, PartialEq, Debug)]
pub enum DbError {
    #[error("bucket error: {0}")]
    BucketError(String),
}
