use rst_common::with_logging::log::debug;
use rstdev_storage::engine::rocksdb::executor::Executor;

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
}

impl ContextHandler {
    pub fn new(db_executor: Executor) -> Self {
        Self {
            db_executor,
            config: None,
        }
    }

    pub fn build_config(&mut self, log_level: String, vessel_dir: String) -> &mut Self {
        debug!("[build config] log_level: {log_level} | vessel_dir: {vessel_dir}");

        let config = Config::new(log_level, vessel_dir);
        self.config = Some(config);
        self
    }

    pub fn db(&self) -> Executor {
        self.db_executor.to_owned()
    }

    pub fn config(&self) -> Option<Config> {
        self.config.clone()
    }
}
