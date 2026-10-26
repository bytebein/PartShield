//! Firma ed25519 del informe.
//!
//! # Forma canónica (lo que se firma)
//!
//! 1. El informe como valor JSON (el objeto que se escribe en
//!    `*.report.json`), con el campo `signature` puesto a `null`.
//!    El campo existe siempre en la v1; si faltara se añade con `null`.
//! 2. Serializado sin ningún espacio ni salto de línea, con las claves de
//!    cada objeto ordenadas por sus bytes UTF-8 (orden lexicográfico de
//!    bytes), a cualquier profundidad. Los arrays conservan su orden.
//! 3. Cadenas con el escapado mínimo de JSON (`"`, `\`, controles; el resto
//!    en UTF-8 tal cual, como hace `serde_json`), enteros en decimal sin
//!    signo `+` ni ceros a la izquierda, `true`/`false`/`null` literales.
//! 4. Los bytes UTF-8 resultantes se firman con ed25519 (RFC 8032, sin
//!    prehash) y la firma se guarda en `signature` como
//!    `{"algo": "ed25519", "public_key": <32 bytes en hex>, "value": <64 bytes en hex>}`
//!    (hex en minúsculas).
//!
//! La firma cubre el contenido, no el formato: reindentar el archivo no la
//! invalida; cambiar cualquier valor, clave u orden de un array sí.
//! La firma se comprueba sobre el informe tal como está escrito, sin migrar.
//!
//! # Claves
//!
//! El archivo de clave privada contiene la semilla de 32 bytes en hex y un
//! salto de línea, con permisos `0600`; junto a él se deja `<ruta>.pub`
//! con la clave pública en hex. [`load_or_create_key`] se niega a usar una
//! clave privada legible por el grupo u otros.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::Signer;
use serde_json::Value;

pub use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::types::{Report, Signature};

pub const ALGO: &str = "ed25519";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let s = s.trim();
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{what}: se esperaban {N} bytes en hex");
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex comprobado");
    }
    Ok(out)
}

/// Clave pública en hex, como se guarda en el informe y en `.pub`.
pub fn public_key_hex(key: &VerifyingKey) -> String {
    hex(key.as_bytes())
}

/// Lee una clave pública en hex (64 caracteres).
pub fn parse_public_key(s: &str) -> Result<VerifyingKey> {
    let bytes = unhex::<32>(s, "clave pública")?;
    VerifyingKey::from_bytes(&bytes).context("clave pública ed25519 no válida")
}

/// Lee una clave pública de un archivo `.pub`.
pub fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("leyendo {}", path.display()))?;
    parse_public_key(&text).with_context(|| format!("en {}", path.display()))
}

fn pub_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".pub");
    PathBuf::from(p)
}

/// Lee la clave de firma de `path`, o crea una nueva (permisos `0600`, y su
/// pública en `<path>.pub`) si no existe.
pub fn load_or_create_key(path: &Path) -> Result<SigningKey> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            if !meta.is_file() {
                bail!("{} no es un archivo de clave", path.display());
            }
            if mode & 0o077 != 0 {
                bail!(
                    "la clave {} tiene permisos {:o}; debe ser 600 (chmod 600 {})",
                    path.display(),
                    mode & 0o777,
                    path.display()
                );
            }
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("leyendo {}", path.display()))?;
            let seed = unhex::<32>(&text, "clave privada")
                .with_context(|| format!("en {}", path.display()))?;
            let key = SigningKey::from_bytes(&seed);
            check_public_matches(path, &key)?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Un .pub sin su clave privada es de otra clave: lo que se firmara
            // ahora no se podría verificar con él. Mejor parar sin escribir.
            let public = pub_path(path);
            if public.exists() {
                bail!(
                    "{} existe pero {} no; es la pública de otra clave. Recupera la \
                     clave privada o aparta {} antes de crear una nueva",
                    public.display(),
                    path.display(),
                    public.display()
                );
            }
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)
                .map_err(|e| anyhow::anyhow!("sin aleatoriedad del sistema: {e}"))?;
            let key = SigningKey::from_bytes(&seed);
            super::atomic::write_new(path, format!("{}\n", hex(&seed)).as_bytes(), 0o600)
                .with_context(|| format!("creando la clave {}", path.display()))?;
            super::atomic::write_new(
                &public,
                format!("{}\n", public_key_hex(&key.verifying_key())).as_bytes(),
                0o644,
            )?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("leyendo {}", path.display())),
    }
}

/// Si hay `<clave>.pub` junto a la privada, tiene que ser su pública.
fn check_public_matches(path: &Path, key: &SigningKey) -> Result<()> {
    let public = pub_path(path);
    let Ok(text) = std::fs::read_to_string(&public) else {
        return Ok(());
    };
    let want = public_key_hex(&key.verifying_key());
    if text.trim() != want {
        bail!(
            "{} no es la clave pública de {}; los informes firmados no se podrían \
             verificar con ella (la correcta es {want})",
            public.display(),
            path.display()
        );
    }
    Ok(())
}

/// Escribe `v` en la forma canónica descrita en el módulo.
fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Bytes que se firman para el informe `v`.
pub fn canonical_bytes(v: &Value) -> Result<Vec<u8>> {
    let mut v = v.clone();
    v.as_object_mut()
        .context("el informe no es un objeto JSON")?
        .insert("signature".into(), Value::Null);
    let mut out = String::new();
    write_canonical(&v, &mut out);
    Ok(out.into_bytes())
}

/// Firma el informe y guarda la firma en `report.signature`.
/// Fírmalo justo antes de escribirlo: cualquier cambio posterior la invalida.
pub fn sign(report: &mut Report, key: &SigningKey) -> Result<()> {
    report.signature = None;
    let v = serde_json::to_value(&*report)?;
    let sig = key.sign(&canonical_bytes(&v)?);
    report.signature = Some(Signature {
        algo: ALGO.into(),
        public_key: public_key_hex(&key.verifying_key()),
        value: hex(&sig.to_bytes()),
    });
    Ok(())
}

/// Comprueba la firma de un informe (el texto del `.report.json`) con la
/// clave pública en la que se confía. La clave que el propio informe
/// declara solo se usa para dar un error claro si no coincide.
pub fn verify_signature(json: &str, public_key: &VerifyingKey) -> Result<()> {
    let v: Value = serde_json::from_str(json).context("el informe no es JSON válido")?;
    let sig = match v.get("signature") {
        None | Some(Value::Null) => bail!("el informe no está firmado"),
        Some(s) => s,
    };
    let sig: Signature =
        serde_json::from_value(sig.clone()).context("la firma del informe está mal formada")?;
    if sig.algo != ALGO {
        bail!("algoritmo de firma no soportado: {}", sig.algo);
    }
    let declared = parse_public_key(&sig.public_key)?;
    if declared != *public_key {
        bail!(
            "el informe está firmado con otra clave ({}), no con {}",
            sig.public_key,
            public_key_hex(public_key)
        );
    }
    let value = ed25519_dalek::Signature::from_bytes(&unhex::<64>(&sig.value, "firma")?);
    public_key
        .verify_strict(&canonical_bytes(&v)?, &value)
        .map_err(|_| anyhow::anyhow!("la firma no corresponde: el informe se ha alterado"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample;

    fn signed_json() -> String {
        let mut r = sample::report();
        sign(&mut r, &sample::key()).unwrap();
        serde_json::to_string_pretty(&r).unwrap()
    }

    #[test]
    fn signs_and_verifies() {
        let json = signed_json();
        verify_signature(&json, &sample::key().verifying_key()).unwrap();
        // Reindentar no cambia el contenido firmado.
        let v: Value = serde_json::from_str(&json).unwrap();
        verify_signature(&v.to_string(), &sample::key().verifying_key()).unwrap();
    }

    #[test]
    fn a_changed_byte_breaks_it() {
        let json = signed_json();
        let at = json.find("/copias/").unwrap() + 1;
        let mut bytes = json.into_bytes();
        bytes[at] = b'C';
        let tampered = String::from_utf8(bytes).unwrap();
        let err = verify_signature(&tampered, &sample::key().verifying_key()).unwrap_err();
        assert!(err.to_string().contains("alterado"), "{err:#}");

        // También un cambio en la propia firma.
        let mut v: Value = serde_json::from_str(&signed_json()).unwrap();
        let s = v["signature"]["value"].as_str().unwrap().to_string();
        let flipped = if s.starts_with('0') { "1" } else { "0" };
        v["signature"]["value"] = Value::String(format!("{flipped}{}", &s[1..]));
        assert!(verify_signature(&v.to_string(), &sample::key().verifying_key()).is_err());
    }

    #[test]
    fn another_key_fails() {
        let other = SigningKey::from_bytes(&[9; 32]);
        let err = verify_signature(&signed_json(), &other.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("otra clave"), "{err:#}");

        // Aunque alguien sustituya la clave declarada por la suya.
        let mut v: Value = serde_json::from_str(&signed_json()).unwrap();
        v["signature"]["public_key"] = Value::String(public_key_hex(&other.verifying_key()));
        let err = verify_signature(&v.to_string(), &other.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("alterado"), "{err:#}");
    }

    #[test]
    fn unsigned_report_fails() {
        let json = serde_json::to_string(&sample::report()).unwrap();
        let err = verify_signature(&json, &sample::key().verifying_key()).unwrap_err();
        assert!(err.to_string().contains("no está firmado"));
    }

    #[test]
    fn canonical_form_is_sorted_and_compact() {
        let v: Value = serde_json::from_str(
            r#"{ "b": [2, 1], "a": {"z": "<&é\"", "y": null}, "signature": {"x": 1} }"#,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(canonical_bytes(&v).unwrap()).unwrap(),
            r#"{"a":{"y":null,"z":"<&é\""},"b":[2,1],"signature":null}"#
        );
    }

    #[test]
    fn creates_a_private_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("firma.key");
        let k1 = load_or_create_key(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let k2 = load_or_create_key(&p).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        let public = load_public_key(&dir.path().join("firma.key.pub")).unwrap();
        assert_eq!(public, k1.verifying_key());

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_or_create_key(&p).unwrap_err();
        assert!(err.to_string().contains("600"), "{err:#}");
    }

    #[test]
    fn refuses_a_public_key_from_another_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("firma.key");
        let public = dir.path().join("firma.key.pub");
        // Un .pub huérfano: no se crea una privada que no le corresponda.
        std::fs::write(&public, "00".repeat(32)).unwrap();
        let err = load_or_create_key(&p).unwrap_err();
        assert!(
            err.to_string().contains("es la pública de otra clave"),
            "{err:#}"
        );
        assert!(!p.exists(), "no se ha escrito ninguna clave privada");

        // Privada y pública que no casan: tampoco se firma con ellas.
        std::fs::remove_file(&public).unwrap();
        load_or_create_key(&p).unwrap();
        std::fs::write(&public, "11".repeat(32)).unwrap();
        let err = load_or_create_key(&p).unwrap_err();
        assert!(
            err.to_string().contains("no es la clave pública"),
            "{err:#}"
        );
    }
}
