use super::types::{CommonError, ToValidate};

pub fn validate(validator: impl ToValidate) -> Result<(), CommonError> {
    validator.validate()
}
