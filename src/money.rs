//! Decimal-safe money (de)serialization.
//!
//! Simplifi sends money as JSON numbers. We never do f64 *arithmetic*: on input the
//! shortest-round-trip string of the JSON number is parsed into `rust_decimal::Decimal`
//! (exact for any realistic money magnitude, <= 15 significant digits); on output a
//! scale-0 Decimal is serialized as an integer, otherwise as the equivalent f64 whose
//! shortest representation reproduces the decimal digits.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use std::str::FromStr;

pub fn parse_decimal(s: &str) -> Result<Decimal, String> {
    Decimal::from_str(s)
        .or_else(|_| Decimal::from_scientific(s))
        .map_err(|e| format!("invalid decimal {s:?}: {e}"))
}

/// serde `with` module for `Option<Decimal>` money fields.
pub mod opt {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Decimal>, D::Error> {
        let v = Option::<serde_json::Value>::deserialize(d)?;
        match v {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::Number(n)) => parse_decimal(&n.to_string())
                .map(Some)
                .map_err(serde::de::Error::custom),
            Some(serde_json::Value::String(s)) => {
                parse_decimal(&s).map(Some).map_err(serde::de::Error::custom)
            }
            Some(_) => Err(serde::de::Error::custom("invalid money value type")),
        }
    }

    pub fn serialize<S: Serializer>(v: &Option<Decimal>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(d) => {
                if d.scale() == 0 {
                    if let Some(i) = d.to_i64() {
                        return s.serialize_i64(i);
                    }
                }
                match d.to_f64() {
                    Some(f) => s.serialize_f64(f),
                    None => s.serialize_str(&d.to_string()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_negative_and_scientific() {
        assert_eq!(parse_decimal("1234.56").unwrap().to_string(), "1234.56");
        assert_eq!(parse_decimal("-0.01").unwrap().to_string(), "-0.01");
        assert_eq!(parse_decimal("1.5e2").unwrap(), Decimal::from(150));
        assert!(parse_decimal("12,34").is_err());
        assert!(parse_decimal("").is_err());
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct M {
        #[serde(with = "super::opt")]
        v: Option<Decimal>,
    }

    #[test]
    fn json_number_string_and_null_inputs() {
        let m: M = serde_json::from_str(r#"{"v": -12.34}"#).unwrap();
        assert_eq!(m.v.unwrap().to_string(), "-12.34");
        let m: M = serde_json::from_str(r#"{"v": "-12.34"}"#).unwrap();
        assert_eq!(m.v.unwrap().to_string(), "-12.34");
        let m: M = serde_json::from_str(r#"{"v": null}"#).unwrap();
        assert!(m.v.is_none());
        assert!(serde_json::from_str::<M>(r#"{"v": [1]}"#).is_err());
    }

    #[test]
    fn integral_decimals_serialize_as_integers() {
        let m = M { v: Some(Decimal::from(-1500)) };
        assert_eq!(serde_json::to_string(&m).unwrap(), r#"{"v":-1500}"#);
        let m = M { v: parse_decimal("4.1").ok() };
        assert_eq!(serde_json::to_string(&m).unwrap(), r#"{"v":4.1}"#);
    }

    #[test]
    fn float_trap_values_roundtrip_exactly() {
        // values whose f64 representation is inexact must still reproduce their digits
        for s in ["4.1", "0.1", "-19.99", "123456.78"] {
            let m = M { v: parse_decimal(s).ok() };
            let json = serde_json::to_string(&m).unwrap();
            let back: M = serde_json::from_str(&json).unwrap();
            assert_eq!(back.v.unwrap().to_string(), s, "roundtrip of {s} via {json}");
        }
    }
}
