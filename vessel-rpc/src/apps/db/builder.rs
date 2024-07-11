use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::engine::rocksdb::options::Options;

use crate::common::types::CommonError;
use crate::config::{RocksDBCommon, RocksDBOptions};
use crate::Config;

use super::Runner;

pub struct Builder {
    cfg: Config,
}

impl Builder {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl Builder {
    pub fn build(
        &mut self,
        db_callback: impl FnOnce(&Config) -> (RocksDBCommon, RocksDBOptions),
    ) -> Result<Runner<DB>, CommonError> {
        let (opts_common, opts_db) = db_callback(&self.cfg);
        let (opts_path, opts_cf_name) = opts_common.get();

        let opts_db_main = opts_db.clone();

        let mut db_opts = Options::new(opts_path, opts_cf_name);
        db_opts.build_default_opts().set_db_opts(move |opt| {
            opt.create_if_missing(opts_db_main.get_create_if_missing());
            opt.create_missing_column_families(opts_db_main.get_create_missing_columns());
            opt.set_error_if_exists(opts_db_main.get_set_error_if_exists());
            opt.set_wal_dir(opts_db_main.get_set_wal_dir());

            opt
        });

        let mut db = DB::new(db_opts).map_err(|err| CommonError::DBError(err.to_string()))?;
        let _ = db
            .build()
            .map_err(|err| CommonError::DBError(err.to_string()))?;

        Ok(Runner::new(db, self.cfg.to_owned()))
    }
}
