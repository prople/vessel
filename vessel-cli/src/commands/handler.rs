use rstdev_storage::engine::rocksdb::executor::Executor;

pub struct ContextHandler {
    db_executor: Executor,
    log_level: String,
    vessel_dir: String
}

impl ContextHandler {
    pub fn new(log_level: String, vessel_dir: String, db_executor: Executor) -> Self {
        Self { db_executor, log_level, vessel_dir }
    }

    pub fn db_executor(&self) -> Executor {
        self.db_executor.to_owned()
    }

    pub fn log_level(&self) -> String {
        self.log_level.to_owned()
    }

    pub fn vessel_dir(&self) -> String {
        self.vessel_dir.to_owned()
    }
}