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

    /// Send a credential
    #[command(name = "send")]
    Send(SendArgs),

    /// Get list of credentials by issuer DID
    #[command(name = "list-credentials-by-did")]
    ListCredentialsByDID(ListCredentialByDIDArgs),
    
    /// Get list of credentials by list of credential ids 
    #[command(name = "list-credentials-by-ids")]
    ListCredentialsIds(ListCredentialByIdsArgs),
    
    /// Get list of holders by issuer DID
    #[command(name = "list-holders-by-did")]
    ListHoldersByDID(ListHolderByDIDArgs),
    
    /// Get list of holders by list of holder ids 
    #[command(name = "list-holders-by-ids")]
    ListHoldersIds(ListHolderByIdsArgs),
}

#[derive(Args, Debug, Clone)]
pub struct SendArgs {
    /// password is a password used when build your account
    #[arg(long, short, required = true)]
    pub password: String,

    /// to_did is the DID of the recipient
    #[arg(long, short, required = true)]
    pub to_did: String,

    /// credential_id is the id of the credential to send
    #[arg(long, short, required = true)]
    pub credential_id: String,
    
    /// address format: https://<host>:<port>/<params> or
    /// https://<domain>/<params>
    #[arg(long, short, required = true)]
    address: String,
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

#[derive(Args, Debug, Clone)]
pub struct ListHolderByDIDArgs {
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
pub struct ListHolderByIdsArgs {
    /// ids is the list of holder ids 
    #[arg(long, short, value_delimiter = ',', num_args = 1..)]
    pub ids: Vec<String>,
}