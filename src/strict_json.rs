//! Duplicate-free JSON values shared by operator artifacts and private result frames.
use serde::{Deserialize, de};
use serde_json::Value;

pub fn parse(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice::<Unique>(bytes).map(|value| value.0)
}

pub(crate) fn value<'de, D: de::Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    Unique::deserialize(deserializer).map(|value| value.0)
}

// serde_json::Value normally accepts duplicate keys. Authoring inputs must not
// acquire different meanings when read by another JSON implementation.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
