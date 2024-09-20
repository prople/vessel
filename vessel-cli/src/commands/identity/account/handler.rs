use rst_common::with_logging::log::debug;

use super::AccountCommands;

pub fn handle_commands(commands: AccountCommands) {
    debug!("account command handler triggered...");

    match commands {
        AccountCommands::GenerateDID { password } => {
            debug!("given password: {password}")
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
