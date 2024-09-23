use rst_common::with_logging::log::debug;

use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::engine::rocksdb::executor::Executor;
use rstdev_storage::engine::rocksdb::options::Options;

use crate::types::CliError;

pub fn setup_database(path: String, cf_name: String) -> Result<Executor, CliError> {
    debug!("db path: {path} | cf name: {cf_name}");

    let mut db_opts = Options::new(path, cf_name.clone());
    db_opts.build_default_opts().set_db_opts(|opt| {
        opt.create_if_missing(true);
        opt.create_missing_column_families(true);
        opt.set_error_if_exists(false);

        opt
    });

    let mut db = DB::new(db_opts).map_err(|err| CliError::DBError(err.to_string()))?;
    let db_instance = db
        .build()
        .map_err(|err| CliError::DBError(err.to_string()))?;

    db.set_db(db_instance);
    Ok(Executor::new(db, cf_name))
}
