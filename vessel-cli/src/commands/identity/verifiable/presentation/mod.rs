use clap::{Args, Subcommand};

pub(crate) mod handler;
pub(crate) mod types;

#[derive(Args, Clone)]
pub struct PresentationArgs {
    #[command(subcommand)]
    pub commands: PresentationCommands,
}

#[derive(Clone, Subcommand)]
pub enum PresentationCommands {
    /// Generate a credential
    #[command(name = "generate")]
    Generate(GenerateArgs),

    /// Send presentation to the verifier
    #[command(name = "send")]
    Send(SendArgs),

    /// Send presentation to the verifier
    #[command(name = "verify")]
    Verify(VerifyArgs),

    /// Get list of credentials by issuer DID
    #[command(name = "list-verifiers-by-did")]
    ListVerifiersByDID(ListVerifiersByDIDArgs),

    /// Get list of credentials by issuer DID
    #[command(name = "get-by-id")]
    GetPresentationByID {
        /// id is the id of the presentation
        #[arg(long, required = true)]
        id: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// id is a verifier id
    #[arg(long, required = true)]
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// password is a password used when build your account
    #[arg(long, short, required = true)]
    pub password: String,

    /// from_did is the DID of the issuer
    #[arg(long, short, required = true)]
    pub from_did: String,

    /// credentials is a list of credential's ids to generate
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub holders: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct SendArgs {
    /// password is a password used when build your account
    #[arg(long, short, required = true)]
    pub password: String,

    /// to_did is the DID of the recipient
    #[arg(long, short, required = true)]
    pub to_did: String,

    /// presentation_id is the id of the credential to send
    #[arg(long, required = true)]
    pub presentation_id: String,

    /// address format: https://<host>:<port>/<params> or
    /// https://<domain>/<params>
    #[arg(long, short, required = true)]
    address: String,
}

#[derive(Args, Debug, Clone)]
pub struct ListVerifiersByDIDArgs {
    /// did is the DID of the issuer
    #[arg(long, short, required = true)]
    pub did: String,
}
