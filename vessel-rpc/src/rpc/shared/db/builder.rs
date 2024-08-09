use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::engine::rocksdb::executor::Executor;
use rstdev_storage::engine::rocksdb::options::Options;

use crate::config::config::Config;
use crate::config::database::{RocksDBCommon, RocksDBOptions};
use crate::rpc::shared::types::CommonError;

use super::merge_operators::bucket::{merge_bucket, MERGE_BUCKET_ID};

pub struct Builder {
    cfg: Config,
}

impl Builder {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub fn build<'a>(
        &'a mut self,
        db_callback: impl FnOnce(&Config) -> (RocksDBCommon, RocksDBOptions),
    ) -> Result<Executor, CommonError> {
        let (opts_common, opts_db) = db_callback(&self.cfg);
        let (opts_path, opts_cf_name) = opts_common.get();

        let opts_db_main = opts_db.clone();

        let mut db_opts = Options::new(opts_path, opts_cf_name.clone());
        db_opts
            .build_default_opts()
            .set_db_opts(move |opt| {
                opt.create_if_missing(opts_db_main.get_create_if_missing());
                opt.create_missing_column_families(opts_db_main.get_create_missing_columns());
                opt.set_error_if_exists(opts_db_main.get_set_error_if_exists());
                opt.set_wal_dir(opts_db_main.get_set_wal_dir());

                opt
            })
            .set_cf_opts(|opt| {
                opt.set_merge_operator_associative(MERGE_BUCKET_ID, merge_bucket);

                opt
            });

        let mut db = DB::new(db_opts).map_err(|err| CommonError::DbError(err.to_string()))?;

        let db_instance = db
            .build()
            .map_err(|err| CommonError::DbError(err.to_string()))?;

        db.set_db(db_instance);

        Ok(Executor::new(db, opts_cf_name))
    }
}
