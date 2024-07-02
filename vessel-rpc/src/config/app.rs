use rst_common::standard::serde::{self, Deserialize};

use crate::common::types::{CommonError, ToValidate};

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "self::serde")]
pub struct App {
    pub(super) host: String,
    pub(super) port: String,
}

impl App {
    pub fn get_app_config(&self) -> (String, String) {
        (self.host.to_owned(), self.port.to_owned())
    }
}

impl Default for App {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: "8080".to_string(),
        }
    }
}

impl ToValidate for App {
    fn validate(&self) -> Result<(), CommonError> {
        if self.host.is_empty() {
            return Err(CommonError::ValidationError(
                "config: app:host is missing".to_string(),
            ));
        }

        if self.port.is_empty() {
            return Err(CommonError::ValidationError(
                "config: app:port is missing".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::path::PathBuf;

    use rstdev_config::format::use_toml;
    use rstdev_config::parser::from_file;
    use rstdev_config::{types::ConfigError, Builder};

    use crate::common::helpers;
    use crate::common::types::CommonError;

    #[test]
    fn test_parse_app_config() -> Result<(), ConfigError> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/config/fixtures");

        let toml_file = format!("{}/config_app.toml", path.display());
        let config_toml = {
            let config_builder: Result<App, ConfigError> =
                Builder::new(from_file(toml_file)).fetch()?.parse(use_toml);

            config_builder
        };

        assert!(!config_toml.is_err());

        let config_app = config_toml.unwrap();
        assert_eq!(config_app.host, "localhost".to_string());
        assert_eq!(config_app.port, "8181".to_string());
        Ok(())
    }

    #[test]
    fn test_validation_failed() -> Result<(), ConfigError> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/config/fixtures");

        let toml_file = format!("{}/config_app.toml", path.display());
        let config_toml = {
            let config_builder: Result<App, ConfigError> =
                Builder::new(from_file(toml_file)).fetch()?.parse(use_toml);

            config_builder
        };
        assert!(!config_toml.is_err());

        let mut config_app = config_toml.unwrap();
        config_app.host = "".to_string();

        let validation = helpers::validate(config_app.clone());
        assert!(validation.is_err());

        let validation_err = validation.unwrap_err();
        assert!(matches!(validation_err, CommonError::ValidationError(_)));
        assert!(validation_err.to_string().contains("host"));

        config_app.host = "host".to_string();
        config_app.port = "".to_string();

        let validation = helpers::validate(config_app.clone());
        assert!(validation.is_err());

        let validation_err = validation.unwrap_err();
        assert!(matches!(validation_err, CommonError::ValidationError(_)));
        assert!(validation_err.to_string().contains("port"));
        Ok(())
    }
}
