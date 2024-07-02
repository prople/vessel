use super::types::{ToValidate, CommonError};

pub fn validate(validator: impl ToValidate) -> Result<(), CommonError> {
    validator.validate()
}