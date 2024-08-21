use rstdev_storage::engine::rocksdb::executor::Executor;

mod config;
mod rpc;

use config::app::App as ConfigApp;
use config::config::Config;
use config::parser::Parser as ConfigParser;

use rpc::shared::db::Builder as DbBuilder;
use rpc::shared::helpers::validate;
use rpc::shared::types::{CommonError, RPCService};

use rpc::identity::Identity;

pub struct VesselRPC {
    config: Config,
    identity: Option<Box<dyn RPCService>>,
}

impl VesselRPC {
    pub fn new<'a>(conf_file: &'a str) -> Result<Self, CommonError> {
        let config = ConfigParser::new(conf_file.to_string())
            .parse()
            .map_err(|err| CommonError::DbError(err.to_string()))?;

        Ok(Self {
            config,
            identity: None,
        })
    }

    pub fn build_app_config(&self) -> Result<ConfigApp, CommonError> {
        let config_app = self.config.app();
        let _ = validate(config_app.to_owned())?;

        Ok(config_app.to_owned())
    }

    pub fn build_db_executor(&self) -> Result<Executor, CommonError> {
        let executor = {
            let _ = validate(self.config.clone())?;
            DbBuilder::new(self.config.clone()).build(|opts| {
                let opts_db = opts.db();
                let opts_db_identity = opts_db.identity.clone();

                let opts_db_common = opts_db_identity.clone().get_common().clone();
                let opts_db_main = opts_db_identity.clone().get_db_options().clone();

                (opts_db_common, opts_db_main)
            })?
        };

        Ok(executor)
    }

    pub fn build_rpc_identity(&mut self) -> Result<&mut Self, CommonError> {
        let executor = self.build_db_executor()?;
        let mut identity = Identity::new(executor);
        identity.build()?;

        self.identity = Some(Box::new(identity));
        Ok(self)
    }
}
