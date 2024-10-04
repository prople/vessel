use prople_jsonrpc_core::objects::RpcProcessor;

mod config;
mod rpc;

pub use config::app::App as ConfigApp;
pub use config::config::Config;

pub mod components {
    use super::*;

    pub use rpc::identity::account::components as account;
    pub use rpc::identity::verifiable::credential::components as credential;
    pub use rpc::identity::verifiable::presentation::components as presentation;
}

use config::parser::Parser as ConfigParser;

pub use rpc::shared::helpers::validate;
pub use rpc::shared::rpc::method::build_rpc_method;
pub use rpc::shared::types::CommonError;

use rpc::Manager;

pub struct VesselRPC {
    config: Config,
    manager: Manager,
}

impl VesselRPC {
    pub fn new<'a>(conf_file: &'a str) -> Result<Self, CommonError> {
        let config = ConfigParser::new(conf_file.to_string())
            .parse()
            .map_err(|err| CommonError::DbError(err.to_string()))?;

        let manager = Manager::new();

        Ok(Self { config, manager })
    }

    pub fn build_app_config(&self) -> Result<ConfigApp, CommonError> {
        let config_app = self.config.app();
        let _ = validate(config_app.to_owned())?;

        Ok(config_app.to_owned())
    }

    pub fn build_rpc_identity(&mut self) -> Result<&mut Self, CommonError> {
        let _ = validate(self.config.db().to_owned())?;

        let _ = self.manager.build_identity_service(self.config.clone())?;
        Ok(self)
    }

    pub fn processor(&self) -> RpcProcessor {
        self.manager.processor()
    }
}
