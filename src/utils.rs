use serde::ser::Serializer;

pub(crate) fn serialize_bytes<S, T>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    serializer.serialize_str(&base64::encode(&bytes))
}

pub(crate) fn serialize_option_bytes<S, T>(bytes: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    match bytes {
        None => serializer.serialize_none(),
        Some(ref bytes) => serializer.serialize_str(&base64::encode(&bytes))
    }
}
