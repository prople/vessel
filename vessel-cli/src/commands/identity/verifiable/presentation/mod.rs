use clap::{Args, Subcommand};

pub(crate) mod handler;

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
    #[arg(long, short, value_delimiter = ',', num_args = 1..)]
    pub credentials: Vec<String>,
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