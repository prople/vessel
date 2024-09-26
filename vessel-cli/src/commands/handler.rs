use rst_common::with_logging::log::debug;
use rstdev_storage::engine::rocksdb::executor::Executor;

use crate::{commands::agents::read_agent_session, types::CliError};

#[derive(Clone)]
pub struct Config {
    log_level: String,
    vessel_dir: String,
}

impl Config {
    fn new(log_level: String, vessel_dir: String) -> Self {
        Self {
            log_level,
            vessel_dir,
        }
    }

    pub fn log_level(&self) -> String {
        self.log_level.clone()
    }

    pub fn vessel_dir(&self) -> String {
        self.vessel_dir.clone()
    }
}

pub struct ContextHandler {
    db_executor: Executor,
    config: Option<Config>,
    agent: Option<String>,
}

impl ContextHandler {
    pub fn new(db_executor: Executor) -> Self {
        Self {
            db_executor,
            config: None,
            agent: None,
        }
    }

    pub fn build_config(&mut self, log_level: String, vessel_dir: String) -> &mut Self {
        debug!("[build config] log_level: {log_level} | vessel_dir: {vessel_dir}");

        let config = Config::new(log_level, vessel_dir);
        self.config = Some(config);
        self
    }

    pub fn set_agent(&mut self, agent_name: Option<String>) -> Result<&mut Self, CliError> {
        match agent_name {
            Some(name) => {
                debug!(
                    "[ctx:set_agent] agent name: {}",
                    name
                );

                self.agent = Some(name) 
            },
            None => {
                let agent = read_agent_session(self)?;
                self.agent = Some(agent);
            }
        }

        Ok(self)
    }

    pub fn db(&self) -> Executor {
        self.db_executor.to_owned()
    }

    pub fn config(&self) -> Option<Config> {
        self.config.clone()
    }

    pub fn agent(&self) -> Option<String> {
        self.agent.clone()
    }
}
