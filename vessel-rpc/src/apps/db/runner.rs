use rst_common::with_tokio::tokio::task::spawn_blocking;
use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::types::Storage;

use crate::apps::types::AppError;
use crate::config::{Database, RocksDBCommon};
use crate::Config;

use super::types::{Instruction, OutputOpts};

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
    pub async fn exec(&self, instruction: Instruction) -> Result<OutputOpts, AppError> {
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

                Ok(OutputOpts::None)
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

                Ok(OutputOpts::SingleByte { value })
            }
            Instruction::MultiGetCf { keys } => {
                let value = spawn_blocking(move || {
                    let cf = db_instance
                        .cf_handle(cf_def.as_str())
                        .map(|val| val.to_owned())
                        .ok_or(AppError::DbError("cf handler failed".to_string()))?;

                    let cf_keys = keys.iter().map(|val| (cf, val));
                    let result = db_instance.multi_get_cf(cf_keys);

                    Ok(result)
                })
                .await
                .map_err(|err| AppError::DbError(err.to_string()))??
                .iter()
                .map(|val| match val.to_owned() {
                    Ok(ok_val) => Ok(ok_val),
                    Err(err) => Err(AppError::DbError(err.to_string())),
                })
                .collect();

                Ok(OutputOpts::MultiBytes { values: value })
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

                Ok(OutputOpts::None)
            }
        }
    }
}
