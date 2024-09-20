use super::AccountCommands;

pub fn handle_commands(commands: AccountCommands) {
    match commands {
        AccountCommands::GenerateDID { password } => {
            println!("password: {}", password)
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