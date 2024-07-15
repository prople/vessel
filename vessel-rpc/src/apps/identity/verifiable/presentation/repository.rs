use rst_common::standard::async_trait::async_trait;
use rstdev_storage::engine::rocksdb::executor::Executor;
use rstdev_storage::engine::rocksdb::types::{
    Instruction as DbInstruction, OutputOpts as DbOutput,
};

use prople_vessel_core::identity::verifiable::presentation::types::{
    PresentationEntityAccessor, PresentationError, RepoBuilder, VerifierEntityAccessor,
};
use prople_vessel_core::identity::verifiable::presentation::{Presentation, Verifier};
use prople_vessel_core::identity::verifiable::types::VerifiableError;

use crate::apps::{DbBucket, DbError};

const PRESENTATION_KEY_ID: &str = "presentation_id";
const PRESENTATION_MERGE_KEY_DID: &str = "merge_presentation";
const VERIFIER_KEY_ID: &str = "verifier_id";

#[derive(Clone)]
pub struct Repository {
    db: Executor,
}

#[allow(dead_code)]
impl Repository {
    pub fn new(db: Executor) -> Self {
        Self { db }
    }

    fn build_presentation_id_key(&self, val: String) -> String {
        format!("{}:{}", PRESENTATION_KEY_ID.to_string(), val)
    }

    fn build_verifier_id_key(&self, val: String) -> String {
        format!("{}:{}", VERIFIER_KEY_ID.to_string(), val)
    }

    fn build_verifier_merge_id_key(&self, val: String) -> String {
        format!("{}:{}", PRESENTATION_MERGE_KEY_DID.to_string(), val)
    }

    async fn check_merge_presentation_did_exists(&self, key: String) -> bool {
        let value_cred = self
            .db
            .exec(DbInstruction::GetCf { key })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            });

        if value_cred.is_err() {
            return false;
        }

        let checker = {
            match value_cred.unwrap() {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            let bucket: Result<DbBucket<Presentation>, DbError> =
                                DbBucket::try_from(val)
                                    .map_err(|err| DbError::BucketError(err.to_string()));

                            bucket
                        })
                        .ok_or(PresentationError::PresentationNotFound)
                        .map_err(|err| PresentationError::ListError(err.to_string()));

                    output
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        };

        return !checker.is_err();
    }
}

#[async_trait]
impl RepoBuilder for Repository {
    type PresentationEntityAccessor = Presentation;
    type VerifierEntityAccessor = Verifier;

    async fn save_presentation_verifier(
        &self,
        data: &Self::VerifierEntityAccessor,
    ) -> Result<(), PresentationError> {
        let verifier_bytes: Vec<u8> = data.to_owned().try_into().map_err(|_| {
            PresentationError::CommonError(VerifiableError::RepoError(
                "unable to convert verifier to bytes".to_string(),
            ))
        })?;

        let verifier_id_key = self.build_verifier_id_key(data.get_id());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: verifier_id_key,
                value: verifier_bytes.clone(),
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        Ok(())
    }

    async fn set_presentation_verifier_verified(
        &self,
        holder: &Self::VerifierEntityAccessor,
    ) -> Result<(), PresentationError> {
        self.save_presentation_verifier(holder).await
    }

    async fn get_by_id(
        &self,
        id: String,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError> {
        let presentation_key = self.build_presentation_id_key(id);
        let value_presentation = self
            .db
            .exec(DbInstruction::GetCf {
                key: presentation_key,
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let presentation = {
            match value_presentation {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            Presentation::try_from(val)
                                .map_err(|err| PresentationError::UnserializeError(err.to_string()))
                        })
                        .ok_or(PresentationError::PresentationNotFound)??;

                    Ok(output)
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        Ok(presentation)
    }

    async fn get_verifier_by_id(
        &self,
        id: String,
    ) -> Result<Self::VerifierEntityAccessor, PresentationError> {
        let verifier_key = self.build_verifier_id_key(id);
        let value_verifier = self
            .db
            .exec(DbInstruction::GetCf { key: verifier_key })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let verifier = {
            match value_verifier {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            Verifier::try_from(val)
                                .map_err(|err| PresentationError::UnserializeError(err.to_string()))
                        })
                        .ok_or(PresentationError::PresentationNotFound)??;

                    Ok(output)
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        Ok(verifier)
    }

    async fn list_vps_by_did_verifier(
        &self,
        _did_verifier: String,
    ) -> Result<Vec<Self::VerifierEntityAccessor>, PresentationError> {
        Err(PresentationError::CommonError(
            VerifiableError::MethodNotImplemented,
        ))
    }

    async fn save(&self, data: &Self::PresentationEntityAccessor) -> Result<(), PresentationError> {
        let presentation_bytes: Vec<u8> = data.to_owned().try_into().map_err(|_| {
            PresentationError::CommonError(VerifiableError::RepoError(
                "unable to convert presentation to bytes".to_string(),
            ))
        })?;

        let presentation_id_key = self.build_presentation_id_key(data.get_id());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: presentation_id_key,
                value: presentation_bytes.clone(),
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        Ok(())
    }
}
