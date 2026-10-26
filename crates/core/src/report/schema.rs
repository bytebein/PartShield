//! Versiones del esquema del informe y migración de informes antiguos.
//!
//! - **v0** (sin `schema_version`): informes anteriores a los tipos
//!   compartidos. `chain[]` y `artifact` llevaban `blake3: "<hex>"` (o `null`
//!   en la cadena) en lugar de `digest: {algo, hex}`, y faltaban
//!   `hash_algo`, `block_stack`, `layout` y `signature`.
//! - **v1**: la forma de `types::Report` con `SCHEMA_VERSION = 1`, descrita
//!   en `schema-v1.json` (JSON Schema 2020-12, en [`SCHEMA_V1`]).
//!
//! [`load_report_value`] lee cualquiera de las dos y devuelve siempre la v1;
//! rechaza un `schema_version` mayor que el que entiende esta versión.
//! La migración solo ocurre en memoria: el archivo nunca se reescribe (y la
//! firma, si la hay, se comprueba sobre el texto original).
//!
//! Al subir `SCHEMA_VERSION`, añade aquí un paso `vN -> vN+1`, un
//! `schema-vN+1.json` y un test con un informe de ejemplo de la versión
//! anterior.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::types::SCHEMA_VERSION;

/// JSON Schema de la v1 del informe.
pub const SCHEMA_V1: &str = include_str!("schema-v1.json");

/// Lee un informe del disco y lo devuelve en la forma del esquema actual.
pub fn load_report_value(path: &Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("leyendo {}", path.display()))?;
    let v: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} no es un informe válido", path.display()))?;
    migrate(v).with_context(|| format!("{} no es un informe válido", path.display()))
}

/// Versión del esquema declarada en un informe (0 si no la declara).
pub fn schema_version_of(v: &Value) -> Result<u64> {
    match v.get("schema_version") {
        None | Some(Value::Null) => Ok(0),
        Some(n) => n
            .as_u64()
            .with_context(|| format!("schema_version no es un entero positivo: {n}")),
    }
}

/// Lleva un informe de cualquier versión conocida a la actual.
pub fn migrate(mut v: Value) -> Result<Value> {
    if !v.is_object() {
        bail!("el informe no es un objeto JSON");
    }
    let version = schema_version_of(&v)?;
    if version > u64::from(SCHEMA_VERSION) {
        bail!(
            "el informe usa el esquema v{version} y esta versión de PartShield ({}) solo \
             entiende hasta la v{SCHEMA_VERSION}; actualiza PartShield para leerlo",
            env!("CARGO_PKG_VERSION")
        );
    }
    if version == 0 {
        v = v0_to_v1(v)?;
    }
    Ok(v)
}

/// `blake3: "<hex>"` → `digest: {algo: "blake3", hex}`.
fn blake3_to_digest(obj: &mut Map<String, Value>, what: &str) -> Result<()> {
    if obj.contains_key("digest") {
        obj.remove("blake3");
        return Ok(());
    }
    let digest = match obj.remove("blake3") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(hex)) => json!({ "algo": "blake3", "hex": hex }),
        Some(other) => bail!("{what}: blake3 no es una cadena: {other}"),
    };
    obj.insert("digest".into(), digest);
    Ok(())
}

fn v0_to_v1(mut v: Value) -> Result<Value> {
    let obj = v.as_object_mut().expect("comprobado antes");
    if let Some(chain) = obj.get_mut("chain").and_then(Value::as_array_mut) {
        for (i, link) in chain.iter_mut().enumerate() {
            let link = link
                .as_object_mut()
                .with_context(|| format!("chain[{i}] no es un objeto"))?;
            blake3_to_digest(link, &format!("chain[{i}]"))?;
        }
    }
    if let Some(artifact) = obj.get_mut("artifact").and_then(Value::as_object_mut) {
        blake3_to_digest(artifact, "artifact")?;
        if artifact["digest"].is_null() {
            bail!("artifact sin hash");
        }
    }
    // v0 solo sabía calcular BLAKE3.
    obj.entry("hash_algo").or_insert(json!("blake3"));
    obj.entry("warnings").or_insert(json!([]));
    for field in ["block_stack", "layout", "raw", "signature"] {
        obj.entry(field).or_insert(Value::Null);
    }
    obj.insert("schema_version".into(), json!(1));
    Ok(v)
}

/// Validador mínimo de JSON Schema para los tests: entiende el subconjunto
/// que usa `schema-v1.json` (type, const, enum, required, properties,
/// additionalProperties: false, items, anyOf, $ref local, minimum, pattern
/// de la forma `^[clase]+$` / `^[clase]{n}$` / `^0x[clase]+$`).
#[cfg(test)]
pub(crate) mod validator {
    use serde_json::Value;

    pub fn validate(schema: &Value, v: &Value) -> Result<(), String> {
        check(schema, schema, v, "$")
    }

    fn type_ok(t: &str, v: &Value) -> bool {
        match t {
            "null" => v.is_null(),
            "boolean" => v.is_boolean(),
            "string" => v.is_string(),
            "object" => v.is_object(),
            "array" => v.is_array(),
            "integer" => v.is_i64() || v.is_u64(),
            "number" => v.is_number(),
            _ => false,
        }
    }

    fn pattern_ok(pat: &str, s: &str) -> bool {
        let (prefix, rest) = match pat.strip_prefix("^0x") {
            Some(r) => ("0x", r),
            None => ("", pat.strip_prefix('^').unwrap_or(pat)),
        };
        let Some(s) = s.strip_prefix(prefix) else {
            return false;
        };
        let class_end = rest.find(']').expect("clase en el patrón");
        let class = &rest[1..class_end];
        let quant = rest[class_end + 1..].trim_end_matches('$');
        let in_class = |c: char| {
            let b: Vec<char> = class.chars().collect();
            b.chunks(3)
                .any(|r| r.len() == 3 && r[1] == '-' && (r[0]..=r[2]).contains(&c))
        };
        let count_ok = match quant {
            "+" => !s.is_empty(),
            q => {
                let n: usize = q.trim_matches(|c| c == '{' || c == '}').parse().unwrap();
                s.chars().count() == n
            }
        };
        count_ok && s.chars().all(in_class)
    }

    fn check(root: &Value, schema: &Value, v: &Value, at: &str) -> Result<(), String> {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            let target = r
                .strip_prefix("#/")
                .unwrap()
                .split('/')
                .fold(root, |s, k| &s[k]);
            return check(root, target, v, at);
        }
        if let Some(c) = schema.get("const") {
            if c != v {
                return Err(format!("{at}: se esperaba {c}, hay {v}"));
            }
        }
        if let Some(e) = schema.get("enum").and_then(Value::as_array) {
            if !e.contains(v) {
                return Err(format!("{at}: {v} no está en {e:?}"));
            }
        }
        if let Some(t) = schema.get("type") {
            let ok = match t {
                Value::String(t) => type_ok(t, v),
                Value::Array(ts) => ts.iter().any(|t| type_ok(t.as_str().unwrap(), v)),
                _ => unreachable!(),
            };
            if !ok {
                return Err(format!("{at}: tipo {t} esperado, hay {v}"));
            }
        }
        if let Some(any) = schema.get("anyOf").and_then(Value::as_array) {
            let errs: Vec<String> = any
                .iter()
                .filter_map(|s| check(root, s, v, at).err())
                .collect();
            if errs.len() == any.len() {
                return Err(errs.join(" | "));
            }
        }
        if let (Some(min), Some(n)) = (schema.get("minimum").and_then(Value::as_i64), v.as_i64()) {
            if n < min {
                return Err(format!("{at}: {n} < {min}"));
            }
        }
        if let (Some(p), Some(s)) = (schema.get("pattern").and_then(Value::as_str), v.as_str()) {
            if !pattern_ok(p, s) {
                return Err(format!("{at}: {s:?} no casa con {p}"));
            }
        }
        if let Some(obj) = v.as_object() {
            let props = schema.get("properties").and_then(Value::as_object);
            if let Some(req) = schema.get("required").and_then(Value::as_array) {
                for k in req {
                    let k = k.as_str().unwrap();
                    if !obj.contains_key(k) {
                        return Err(format!("{at}: falta {k}"));
                    }
                }
            }
            for (k, val) in obj {
                match props.and_then(|p| p.get(k)) {
                    Some(s) => check(root, s, val, &format!("{at}.{k}"))?,
                    None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                        return Err(format!("{at}: propiedad no prevista {k}"))
                    }
                    None => {}
                }
            }
        }
        if let (Some(items), Some(arr)) = (schema.get("items"), v.as_array()) {
            for (i, x) in arr.iter().enumerate() {
                check(root, items, x, &format!("{at}[{i}]"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::validator::validate;
    use super::*;
    use crate::report::sample;

    /// Un informe real de antes de `schema_version` (v0), recortado.
    const V0: &str = r#"{
      "tool": "partshield",
      "version": "0.1.0",
      "started": "2026-10-20T10:00:00+02:00",
      "finished": "2026-10-20T10:01:00+02:00",
      "source": "/home",
      "device": "/dev/loop0",
      "superblock": null,
      "modes": [{"mode": "send", "allowed": true, "reasons": ["ok"]}],
      "mode": "send",
      "artifact": {
        "stream": "/copias/home-1.btrfs.zst",
        "snapshot": "/home/.partshield-home-1",
        "blake3": "ab12",
        "compressed_bytes": 10,
        "stream_bytes": 20
      },
      "parent_report": null,
      "chain": [
        {"path": "/copias/home-0.btrfs.zst", "blake3": null},
        {"path": "/copias/home-1.btrfs.zst", "blake3": "ab12"}
      ],
      "verification": {"verdict": "valid", "steps": [], "comparison": null},
      "commands": [{"command": "btrfs send", "exit_code": 0, "duration_ms": 5}],
      "error": null
    }"#;

    fn schema() -> Value {
        serde_json::from_str(SCHEMA_V1).expect("schema-v1.json es JSON")
    }

    #[test]
    fn migrates_a_v0_report() {
        let v = migrate(serde_json::from_str(V0).unwrap()).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["hash_algo"], "blake3");
        assert_eq!(
            v["artifact"]["digest"],
            json!({"algo": "blake3", "hex": "ab12"})
        );
        assert!(v["artifact"].get("blake3").is_none());
        assert_eq!(v["chain"][0]["digest"], Value::Null);
        assert_eq!(v["chain"][1]["digest"]["hex"], "ab12");
        assert!(v["chain"][1].get("blake3").is_none());
        assert!(v["signature"].is_null());
        validate(&schema(), &v).unwrap();
        // La cadena migrada se deserializa con el tipo actual.
        let chain: Vec<crate::types::StreamRef> =
            serde_json::from_value(v["chain"].clone()).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn a_v1_report_is_left_as_is_and_matches_the_schema() {
        let v = serde_json::to_value(sample::report()).unwrap();
        assert_eq!(migrate(v.clone()).unwrap(), v);
        validate(&schema(), &v).unwrap();
        let mut signed = sample::report();
        crate::report::sign::sign(&mut signed, &sample::key()).unwrap();
        validate(&schema(), &serde_json::to_value(&signed).unwrap()).unwrap();
    }

    #[test]
    fn the_schema_describes_every_top_level_field() {
        let v = serde_json::to_value(sample::report()).unwrap();
        let s = schema();
        let props = s["properties"].as_object().unwrap();
        let mut a: Vec<_> = v.as_object().unwrap().keys().collect();
        let mut b: Vec<_> = props.keys().collect();
        a.sort();
        b.sort();
        assert_eq!(a, b);
        assert_eq!(s["properties"]["schema_version"]["const"], SCHEMA_VERSION);
    }

    #[test]
    fn the_validator_catches_a_bad_report() {
        let mut v = serde_json::to_value(sample::report()).unwrap();
        v["chain"][0]["digest"]["algo"] = json!("md5");
        assert!(validate(&schema(), &v).is_err());
    }

    #[test]
    fn rejects_a_newer_schema() {
        let mut v = serde_json::to_value(sample::report()).unwrap();
        v["schema_version"] = json!(SCHEMA_VERSION + 1);
        let err = migrate(v).unwrap_err().to_string();
        assert!(err.contains(&format!("v{}", SCHEMA_VERSION + 1)), "{err}");
        assert!(err.contains("actualiza PartShield"), "{err}");
    }

    #[test]
    fn loads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("viejo.report.json");
        std::fs::write(&p, V0).unwrap();
        assert_eq!(load_report_value(&p).unwrap()["schema_version"], 1);
        std::fs::write(dir.path().join("roto.json"), "{").unwrap();
        assert!(load_report_value(&dir.path().join("roto.json")).is_err());
    }
}
