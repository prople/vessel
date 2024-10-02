use rst_common::with_logging::log::debug;

use crate::commands::handler::ContextHandler;

use super::AccountCommands;

pub async fn handle_commands(_ctx: &ContextHandler, commands: AccountCommands) {
    debug!("account command handler triggered...");

    match commands {
        AccountCommands::GenerateDID { password } => {
            debug!("[GenerateDID] given password: {password}")
        }

        AccountCommands::BuildDIDURI(args) => {
            println!("params: {:?}", args)
        }

        AccountCommands::ResolveDIDURI { uri } => {
            println!("uri: {}", uri)
        }

        AccountCommands::ResolveDIDDoc { uri } => {
            println!("uri: {}", uri)
        }

        AccountCommands::RemoveDID { did } => {
            println!("did: {}", did)
        }

        AccountCommands::GetAccountDID { did } => {
            println!("did: {}", did)
        }
    }
}
