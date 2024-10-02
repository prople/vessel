use rstdev_storage::engine::rocksdb::executor::Executor;
use rstdev_storage::engine::rocksdb::types::{Instruction, OutputOpts};

use super::types::{AgentName, Key, Model, ModelError};

pub struct DB {
    db: Executor,
}

impl DB {
    pub fn new(db: Executor) -> Self {
        Self { db }
    }

    pub async fn save(&self, agent_name: AgentName, model: impl Model) -> Result<(), ModelError> {
        let (key, value) = model
            .build(agent_name)
            .map_err(|err| ModelError::DatabaseError(err.to_string()))?;

        let key_str: String = key.try_into().map_err(|_| {
            ModelError::DeserializeError(String::from("unable to revert key to string"))
        })?;

        let _ = self
            .db
            .exec(Instruction::SaveCf {
                key: key_str,
                value: value.to_vec(),
            })
            .await
            .map_err(|err| ModelError::DatabaseError(err.to_string()))?;

        Ok(())
    }

    pub async fn get_model<O, ValueFn>(&self, key: Key, value_fn: ValueFn) -> Result<O, ModelError>
    where
        O: Model,
        ValueFn: FnOnce(Vec<u8>) -> Result<O, ModelError>,
    {
        let key_str: String = key.try_into().map_err(|_| {
            ModelError::DeserializeError(String::from("unable to revert key to string"))
        })?;

        let out = self
            .db
            .exec(Instruction::GetCf { key: key_str })
            .await
            .map_err(|err| ModelError::DatabaseError(err.to_string()))?;

        match out {
            OutputOpts::SingleByte { value } => {
                let val =
                    value.ok_or(ModelError::DatabaseError(String::from("value not found")))?;

                value_fn(val) 
            }
            _ => Err(ModelError::DatabaseError(String::from(
                "invalid output return type",
            ))),
        }
    }
}
