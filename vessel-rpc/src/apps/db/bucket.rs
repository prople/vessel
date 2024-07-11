use rst_common::standard::serde::de::DeserializeOwned;
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use super::types::DbError;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Bucket<T>
where
    T: TryInto<Vec<u8>> + Serialize,
{
    collections: Vec<T>,
}

#[allow(dead_code)]
impl<T> Bucket<T>
where
    T: TryInto<Vec<u8>> + Serialize + DeserializeOwned,
{
    pub fn new() -> Self {
        Self {
            collections: Vec::new(),
        }
    }

    pub fn add(&mut self, val: T) {
        self.collections.push(val)
    }
}

impl<T> TryInto<Vec<u8>> for Bucket<T>
where
    T: TryInto<Vec<u8>> + Serialize,
{
    type Error = DbError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json =
            serde_json::to_vec(&self).map_err(|err| DbError::BucketError(err.to_string()))?;

        Ok(json)
    }
}

impl<T> TryFrom<Vec<u8>> for Bucket<T>
where
    T: TryInto<Vec<u8>> + Serialize + DeserializeOwned,
{
    type Error = DbError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bucket: Self =
            serde_json::from_slice(&value).map_err(|err| DbError::BucketError(err.to_string()))?;
        Ok(bucket)
    }
}

impl<T> ToJSON for Bucket<T>
where
    T: TryInto<Vec<u8>> + Serialize,
{
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    #[serde(crate = "self::serde")]
    struct FakeObj {
        msg: String,
    }

    impl TryInto<Vec<u8>> for FakeObj {
        type Error = DbError;

        fn try_into(self) -> Result<Vec<u8>, Self::Error> {
            let json =
                serde_json::to_vec(&self).map_err(|err| DbError::BucketError(err.to_string()))?;

            Ok(json)
        }
    }

    #[test]
    fn test_build_bucket_to_bytes() {
        let mut bucket = Bucket::new();

        bucket.add(FakeObj {
            msg: "hello world 1".to_string(),
        });

        bucket.add(FakeObj {
            msg: "hello world 2".to_string(),
        });

        bucket.add(FakeObj {
            msg: "hello world 3".to_string(),
        });

        let bytes: Result<Vec<u8>, DbError> = bucket.try_into();
        assert!(!bytes.is_err());
    }

    #[test]
    fn test_from_json() {
        let mut bucket = Bucket::new();

        bucket.add(FakeObj {
            msg: "hello world 1".to_string(),
        });

        bucket.add(FakeObj {
            msg: "hello world 2".to_string(),
        });

        bucket.add(FakeObj {
            msg: "hello world 3".to_string(),
        });

        let json_builder = bucket.to_json();
        assert!(!json_builder.is_err());

        let from_json: Result<Bucket<FakeObj>, DbError> =
            json_builder.unwrap().as_bytes().to_vec().try_into();

        assert!(!from_json.is_err());
    }
}
