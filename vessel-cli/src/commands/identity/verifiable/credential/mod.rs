use clap::{Args, Subcommand};

pub(crate) mod handler;
pub(crate) mod types;

#[derive(Args, Clone)]
pub struct CredentialArgs {
    #[command(subcommand)]
    pub commands: CredentialCommands,
}

#[derive(Clone, Subcommand)]
pub enum CredentialCommands {
    /// Generate a credential
    #[command(name = "generate")]
    Generate(GenerateArgs),

    /// Get list of credentials by issuer DID
    #[command(name = "list-by-did")]
    ListCredentialsByDID(ListCredentialByDIDArgs),
    
    /// Get list of credentials by list of credential ids 
    #[command(name = "list-by-ids")]
    ListCredentialsIds(ListCredentialByIdsArgs),
}

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// password is a password used when build your account
    #[arg(long, short, required = true)]
    pub password: String,

    /// from_did is the DID of the issuer
    #[arg(long, short, required = true)]
    pub from_did: String,

    /// credential is a JSON string that contains the credential data
    #[arg(long, short, required = true)]
    pub credential: String,
}

#[derive(Args, Debug, Clone)]
pub struct ListCredentialByDIDArgs {
    /// did is the DID of the issuer
    #[arg(long, short, required = true)]
    pub did: String,

    /// page is the page number to load 
    #[arg(long, short)]
    pub page: Option<usize>,

    /// limit is the number of items to load
    #[arg(long, short)]
    pub limit: Option<usize>,
}

#[derive(Args, Debug, Clone)]
pub struct ListCredentialByIdsArgs {
    /// ids is the list of credential ids 
    #[arg(long, short, value_delimiter = ',', num_args = 1..)]
    pub ids: Vec<String>,
}