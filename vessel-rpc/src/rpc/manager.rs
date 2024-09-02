use prople_jsonrpc_core::objects::RpcProcessor;

use crate::config::config::Config;

use crate::rpc::shared::db::Builder as DbBuilder;
use crate::rpc::shared::types::CommonError;
use super::shared::types::RPCService;

use crate::rpc::identity::Identity;

pub struct Manager {
    processor: RpcProcessor,
}

impl Manager {
    pub fn new() -> Self {
        let processor = RpcProcessor::default();
        Self {
            processor,
        }
    }

    pub fn build_identity_service(&mut self, conf: Config) -> Result<&mut Self, CommonError> {
        let mut db_builder = DbBuilder::new(conf);
        let db_executor = db_builder.build(|opts| {
            let opts_db = opts.db();
            let opts_db_identity = opts_db.identity.clone();

            let opts_db_common = opts_db_identity.clone().get_common().clone();
            let opts_db_main = opts_db_identity.clone().get_db_options().clone();

            (opts_db_common, opts_db_main)
        })?;

        let mut identity_rpc = Identity::new(db_executor);

        let _ = identity_rpc.build()?;
        let _ = identity_rpc.setup_rpc()?;
        let routes = identity_rpc.routes();

        if routes.len() < 1 {
            return Err(CommonError::RpcError(String::from("identity doesn't have any routes")))
        }

        for route in routes.iter() {
            self.processor.register_route(route.clone());
        }

        Ok(self)
    }

    pub fn processor(&self) -> RpcProcessor {
        self.processor.clone()
    }
}
