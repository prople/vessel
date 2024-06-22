use rst_common::with_errors::thiserror::{self, Error};

pub const VP_TYPE: &str = "VerifiablePresentation";

#[derive(Debug, Error, Clone)]
pub enum VerifiableError {
    #[error("did error: {0}")]
    DIDError(String),

    #[error("unable to generate vc: {0}")]
    VCGenerateError(String),

    #[error("unable to process incoming vc: {0}")]
    VCReceiveError(String),

    #[error("unable to send vc: {0}")]
    VCSendError(String),

    #[error("unable to confirm vc: {0}")]
    VCConfirmError(String),

    #[error("unable to verify vc: {0}")]
    VCVerifyError(String),

    #[error("unable to list vc: {0}")]
    VCListError(String),

    #[error("unable to generate vp: {0}")]
    VPGenerateError(String),

    #[error("repo error: {0}")]
    RepoError(String),

    #[error("parse multiaddr error: {0}")]
    ParseMultiAddrError(String),

    #[error("validaiton error: {0}")]
    ValidationError(String),

    #[error("unknown error: {0}")]
    UnknownError(String),
}

/// `PaginationParams` used when we need to load a list of something from persistent storage
/// it assumed using common pagination params contains of page, limit and skip
pub struct PaginationParams {
    pub page: usize,
    pub limit: usize,
    pub skip: usize,
}
