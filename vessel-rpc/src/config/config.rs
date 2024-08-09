use rst_common::standard::serde::{self, Deserialize};

use crate::rpc::shared::types::{CommonError, ToValidate};

use super::app::App;
use super::database::Database;

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "self::serde")]
pub struct Config {
    pub(super) database: Database,
    pub(super) app: App,
}

impl Config {
    pub fn app(&self) -> &App {
        &self.app
    }

    pub fn db(&self) -> &Database {
        &self.database
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: Database::default(),
            app: App::default(),
        }
    }
}

impl ToValidate for Config {
    fn validate(&self) -> Result<(), CommonError> {
        _ = self.app.validate()?;
        _ = self.database.validate()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::shared::helpers;
    use crate::rpc::shared::types::CommonError;

    #[test]
    fn test_validation_failed() {
        let cfg = Config::default();
        let validation = helpers::validate(cfg);
        assert!(validation.is_err());
        assert!(matches!(
            validation.unwrap_err(),
            CommonError::ValidationError(_)
        ))
    }
}
