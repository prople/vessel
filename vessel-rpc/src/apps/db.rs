use rst_common::with_tokio::tokio::task::spawn_blocking;

use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::engine::rocksdb::options::Options;
use rstdev_storage::types::Storage;

use crate::common::types::CommonError;
use crate::config::{Database, RocksDBCommon, RocksDBOptions};
use crate::Config;

use super::types::AppError;

pub enum Instruction {
    SaveCf { key: String, value: Vec<u8> },
    GetCf { key: String },
    RemoveCf { key: String },
}

#[derive(Clone)]
pub struct Runner<TStorage>
where
    TStorage: Storage<Instance = DB>,
{
    instance: TStorage,
    cfg: Config,
}

impl<TStorage> Runner<TStorage>
where
    TStorage: Storage<Instance = DB>,
{
    pub fn new(instance: TStorage, cfg: Config) -> Self {
        Self { instance, cfg }
    }

    pub fn get_cf_def(&self, callback: impl FnOnce(&Database) -> RocksDBCommon) -> String {
        let common = callback(self.cfg.db());
        let (_, cf) = common.get();

        cf
    }
}

impl Runner<DB> {
    pub async fn exec(&self, instruction: Instruction) -> Result<Option<Vec<u8>>, AppError> {
        let instance = self.instance.clone().get_instance();

        let db_instance = instance
            .db
            .clone()
            .map(|val| val)
            .ok_or(AppError::DbError("db instance is missing".to_string()))?;

        let cf_def = self.get_cf_def(|db| db.identity.get_common()).clone();

        match instruction {
            Instruction::SaveCf { key, value } => {
                let _ = spawn_blocking(move || {
                    let cf = db_instance
                        .cf_handle(cf_def.as_str())
                        .map(|val| val.to_owned())
                        .ok_or(AppError::DbError("cf handler failed".to_string()))?;

                    let result = db_instance
                        .put_cf(cf, key, value)
                        .map_err(|err| AppError::DbError(err.to_string()));

                    result
                })
                .await
                .map_err(|err| AppError::DbError(err.to_string()))?;

                Ok(None)
            }
            Instruction::GetCf { key } => {
                let value = spawn_blocking(move || {
                    let cf = db_instance
                        .cf_handle(cf_def.as_str())
                        .map(|val| val.to_owned())
                        .ok_or(AppError::DbError("cf handler failed".to_string()))?;

                    let result = db_instance
                        .get_cf(cf, key)
                        .map_err(|err| AppError::DbError(err.to_string()))
                        .map(|val| val);

                    result
                })
                .await
                .map_err(|err| AppError::DbError(err.to_string()))??;

                Ok(value)
            }
            Instruction::RemoveCf { key } => {
                let _ = spawn_blocking(move || {
                    let cf = db_instance
                        .cf_handle(cf_def.as_str())
                        .map(|val| val.to_owned())
                        .ok_or(AppError::DbError("cf handler failed".to_string()))?;

                    let result = db_instance
                        .delete_cf(cf, key)
                        .map_err(|err| AppError::DbError(err.to_string()))
                        .map(|val| val);

                    result
                })
                .await
                .map_err(|err| AppError::DbError(err.to_string()))?;

                Ok(None)
            }
        }
    }
}

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
