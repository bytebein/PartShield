//! Informe en HTML para personas: un solo archivo, sin recursos externos,
//! con el CSS dentro, legible en el móvil e impreso. Todo texto que viene
//! del informe pasa por [`esc`].
//!
//! El HTML es una vista: la firma cubre el JSON, que es el informe de
//! referencia.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;

use crate::types::{
    Assessment, ChecksumStatus, Digest, LayerKind, Mode, Report, StepStatus, StreamRef, Verdict,
};

/// Escapa texto para meterlo en HTML (contenido o atributo entre comillas).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn escp(p: &Path) -> String {
    esc(&p.to_string_lossy())
}

/// Tamaño legible en unidades binarias, con los bytes exactos.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {} ({n} B)", UNITS[u]).replace('.', ",")
    }
}

fn digest(d: Option<&Digest>) -> String {
    match d {
        Some(d) => format!(
            "<code class=\"hash\">{}:{}</code>",
            esc(&format!("{:?}", d.algo).to_lowercase()),
            esc(&d.hex)
        ),
        None => "<span class=\"muted\">sin hash</span>".into(),
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Send => "send (btrfs send por subvolumen)",
        Mode::Partclone => "partclone (bloques usados)",
        Mode::Raw => "raw (sector a sector)",
    }
}

fn layer_name(k: LayerKind) -> &'static str {
    match k {
        LayerKind::Disk => "Disco",
        LayerKind::Partition => "Partición",
        LayerKind::Luks => "LUKS",
        LayerKind::LvmLv => "Volumen lógico LVM",
        LayerKind::Loop => "Loop",
        LayerKind::Other => "Otra",
    }
}

fn verdict_banner(r: &Report) -> String {
    let (class, mark, title, text) = match r.verdict() {
        Verdict::Valid => (
            "valid",
            "✓",
            "COPIA VÁLIDA",
            "Se restauró en un entorno de prueba y todas las comprobaciones pasaron.",
        ),
        Verdict::Reduced => (
            "reduced",
            "!",
            "COPIA VÁLIDA CON COMPROBACIÓN REDUCIDA",
            "No falló nada, pero algún paso de verificación se omitió; \
             revisa los pasos marcados como omitidos.",
        ),
        Verdict::Invalid => (
            "invalid",
            "✗",
            "COPIA NO VÁLIDA",
            "No se puede confiar en esta copia para restaurar. Mira el error y los pasos fallidos.",
        ),
    };
    format!(
        "<section class=\"verdict {class}\" role=\"status\">\
         <span class=\"mark\" aria-hidden=\"true\">{mark}</span>\
         <div><h1>Veredicto: {title}</h1><p>{text}</p></div></section>\n"
    )
}

fn row(out: &mut String, k: &str, v: &str) {
    let _ = writeln!(out, "<tr><th scope=\"row\">{k}</th><td>{v}</td></tr>");
}

fn opt_path(p: Option<&Path>) -> String {
    p.map(escp)
        .unwrap_or_else(|| "<span class=\"muted\">—</span>".into())
}

fn opt_str(s: Option<&str>) -> String {
    s.map(esc)
        .unwrap_or_else(|| "<span class=\"muted\">—</span>".into())
}

fn names(list: &[&str]) -> String {
    if list.is_empty() {
        "<span class=\"muted\">ninguna</span>".into()
    } else {
        list.iter()
            .map(|n| format!("<code>{}</code>", esc(n)))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn origin(out: &mut String, r: &Report) {
    out.push_str("<section><h2>Origen</h2><table class=\"kv\">\n");
    row(out, "Origen", &format!("<code>{}</code>", escp(&r.source)));
    row(out, "Dispositivo", &opt_path(r.device.as_deref()));
    if let Some(sb) = &r.superblock {
        row(out, "UUID del sistema de archivos", &esc(&sb.fsid));
        row(
            out,
            "Etiqueta",
            &opt_str(Some(sb.label.as_str()).filter(|l| !l.is_empty())),
        );
        row(out, "Generación", &sb.generation.to_string());
        row(
            out,
            "Ocupado / total",
            &format!(
                "{} / {}",
                human_bytes(sb.bytes_used),
                human_bytes(sb.total_bytes)
            ),
        );
        row(out, "Dispositivos", &sb.num_devices.to_string());
        row(
            out,
            "Sector / nodo",
            &format!("{} B / {} B", sb.sectorsize, sb.nodesize),
        );
        let checksum = match &sb.checksum {
            ChecksumStatus::Valid => "crc32c del superbloque comprobado".to_string(),
            ChecksumStatus::NotVerified { csum_type } => {
                format!("no comprobado (tipo de checksum {csum_type})")
            }
        };
        row(out, "Checksum del superbloque", &esc(&checksum));
    } else {
        row(
            out,
            "Superbloque",
            "<span class=\"muted\">no se llegó a leer</span>",
        );
    }
    out.push_str("</table>\n<h3>Capas de bloque</h3>\n");
    match r.block_stack.as_ref().filter(|b| !b.layers.is_empty()) {
        None => out.push_str("<p class=\"muted\">No se detectaron capas.</p>\n"),
        Some(stack) => {
            out.push_str(
                "<p class=\"muted\">De arriba (el dispositivo con el Btrfs) hacia abajo (el disco).</p>\
                 <div class=\"scroll\"><table><thead><tr><th>Capa</th><th>Dispositivo</th>\
                 <th>UUID</th><th>Detalle</th></tr></thead><tbody>\n",
            );
            for l in &stack.layers {
                let _ = writeln!(
                    out,
                    "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    layer_name(l.kind),
                    escp(&l.device),
                    opt_str(l.uuid.as_deref()),
                    opt_str(l.detail.as_deref())
                );
            }
            out.push_str("</tbody></table></div>\n");
        }
    }
    out.push_str("</section>\n");
}

fn features(out: &mut String, r: &Report) {
    out.push_str("<section><h2>Features del sistema de archivos</h2>\n");
    let Some(sb) = &r.superblock else {
        out.push_str("<p class=\"muted\">Sin superbloque no hay features.</p></section>\n");
        return;
    };
    let f = &sb.features;
    out.push_str("<table class=\"kv\">\n");
    row(out, "compat", &format!("<code>{:#x}</code>", f.compat));
    row(
        out,
        "compat_ro",
        &format!(
            "<code>{:#x}</code> {}",
            f.compat_ro.0,
            names(&f.compat_ro.names())
        ),
    );
    row(
        out,
        "incompat",
        &format!(
            "<code>{:#x}</code> {}",
            f.incompat.0,
            names(&f.incompat.names())
        ),
    );
    let unknown = [
        ("compat_ro", f.compat_ro.unknown()),
        ("incompat", f.incompat.unknown()),
    ];
    for (name, bits) in unknown {
        if bits != 0 {
            row(
                out,
                &format!("{name} desconocidos"),
                &format!("<strong class=\"bad-text\">⚠ <code>{bits:#x}</code>: esta versión no conoce esos bits</strong>"),
            );
        }
    }
    out.push_str("</table></section>\n");
}

fn modes(out: &mut String, r: &Report) {
    out.push_str(
        "<section><h2>Modos de copia</h2>\n<div class=\"scroll\"><table><thead><tr>\
         <th>Modo</th><th>¿Permitido?</th><th>Por qué</th></tr></thead><tbody>\n",
    );
    let used = r.mode;
    for Assessment {
        mode,
        allowed,
        reasons,
    } in &r.modes
    {
        let chosen = if *mode == used {
            " <span class=\"tag\">usado</span>"
        } else {
            ""
        };
        let allowed = if *allowed {
            "<span class=\"ok-text\">✓ Sí</span>"
        } else {
            "<span class=\"bad-text\">✗ No</span>"
        };
        let reasons: String = reasons
            .iter()
            .map(|x| format!("<li>{}</li>", esc(x)))
            .collect();
        let _ = writeln!(
            out,
            "<tr><td>{}{chosen}</td><td>{allowed}</td><td><ul>{reasons}</ul></td></tr>",
            mode_name(*mode)
        );
    }
    if r.modes.is_empty() {
        out.push_str("<tr><td colspan=\"3\" class=\"muted\">No se evaluó ningún modo.</td></tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    let _ = writeln!(
        out,
        "<p>Modo usado: <strong>{}</strong>.</p></section>",
        mode_name(used)
    );
}

fn stream_size(r: &Report, s: &StreamRef) -> String {
    if let Some(a) = r.artifact.as_ref().filter(|a| a.stream == s.path) {
        return format!(
            "{}<br><span class=\"muted\">sin comprimir: {}</span>",
            human_bytes(a.compressed_bytes),
            human_bytes(a.stream_bytes)
        );
    }
    if let Some(c) = &s.chunks {
        return human_bytes(c.parts.iter().map(|p| p.bytes).sum());
    }
    match std::fs::metadata(&s.path) {
        Ok(m) => format!(
            "{}<br><span class=\"muted\">en disco al generar este HTML</span>",
            human_bytes(m.len())
        ),
        Err(_) => "<span class=\"muted\">desconocido</span>".into(),
    }
}

fn chain(out: &mut String, r: &Report) {
    out.push_str("<section><h2>Copia y cadena de streams</h2>\n");
    if let Some(a) = &r.artifact {
        out.push_str("<table class=\"kv\">\n");
        row(out, "Stream", &format!("<code>{}</code>", escp(&a.stream)));
        row(
            out,
            "Snapshot",
            &format!("<code>{}</code>", escp(&a.snapshot)),
        );
        row(out, "Comprimido", &human_bytes(a.compressed_bytes));
        row(out, "Sin comprimir", &human_bytes(a.stream_bytes));
        row(out, "Hash", &digest(Some(&a.digest)));
        out.push_str("</table>\n");
    } else {
        out.push_str("<p class=\"muted\">No se llegó a producir ningún stream.</p>\n");
    }
    if let Some(p) = &r.parent_report {
        let _ = writeln!(
            out,
            "<p>Incremental sobre el informe <code>{}</code>.</p>",
            escp(p)
        );
    }
    if !r.chain.is_empty() {
        out.push_str(
            "<p class=\"muted\">Para restaurar, se aplican en este orden.</p>\
             <div class=\"scroll\"><table><thead><tr><th>#</th><th>Tipo</th><th>Archivo</th>\
             <th>Tamaño</th><th>Hash</th></tr></thead><tbody>\n",
        );
        for (i, s) in r.chain.iter().enumerate() {
            let kind = if i == 0 { "completo" } else { "incremental" };
            let mut extra = String::new();
            if let Some(crate::types::Encryption::Age { recipients }) = &s.encryption {
                let _ = write!(
                    extra,
                    "<br><span class=\"muted\">cifrado con age para {}</span>",
                    esc(&recipients.join(", "))
                );
            }
            if let Some(c) = &s.chunks {
                let _ = write!(
                    extra,
                    "<br><span class=\"muted\">en {} trozos de {}</span>",
                    c.parts.len(),
                    esc(&human_bytes(c.chunk_bytes))
                );
            }
            let _ = writeln!(
                out,
                "<tr><td>{}</td><td>{kind}</td><td><code>{}</code>{extra}</td><td>{}</td><td>{}</td></tr>",
                i + 1,
                escp(&s.path),
                stream_size(r, s),
                digest(s.digest.as_ref())
            );
        }
        out.push_str("</tbody></table></div>\n");
    }
    if let Some(l) = &r.layout {
        out.push_str("<h3>Disposición del disco</h3><table class=\"kv\">\n");
        row(out, "UUID", &opt_str(l.fs_uuid.as_deref()));
        for (name, s) in [
            ("Tabla de particiones", &l.partition_table),
            ("Partición EFI", &l.esp),
        ] {
            let v = match s {
                Some(s) => format!(
                    "<code>{}</code><br>{}",
                    escp(&s.path),
                    digest(s.digest.as_ref())
                ),
                None => "<span class=\"muted\">no copiada</span>".into(),
            };
            row(out, name, &v);
        }
        out.push_str("</table>\n");
        if !l.notes.is_empty() {
            out.push_str("<ul>");
            for n in &l.notes {
                let _ = write!(out, "<li>{}</li>", esc(n));
            }
            out.push_str("</ul>\n");
        }
    }
    out.push_str("</section>\n");
}

fn verification(out: &mut String, r: &Report) {
    out.push_str("<section><h2>Verificación</h2>\n");
    let Some(v) = &r.verification else {
        out.push_str("<p class=\"bad-text\"><strong>✗ La copia no llegó a verificarse.</strong></p></section>\n");
        return;
    };
    out.push_str(
        "<div class=\"scroll\"><table><thead><tr><th>Paso</th><th>Resultado</th><th>Detalle</th>\
         </tr></thead><tbody>\n",
    );
    for s in &v.steps {
        let status = match s.status {
            StepStatus::Passed => "<span class=\"ok-text\">✓ Superado</span>",
            StepStatus::Failed => "<span class=\"bad-text\">✗ Fallido</span>",
            StepStatus::Skipped => "<span class=\"warn-text\">– Omitido</span>",
        };
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td>{status}</td><td class=\"detail\">{}</td></tr>",
            esc(s.name),
            esc(&s.detail)
        );
    }
    if v.steps.is_empty() {
        out.push_str("<tr><td colspan=\"3\" class=\"muted\">Sin pasos.</td></tr>\n");
    }
    out.push_str("</tbody></table></div>\n<h3>Diferencias encontradas</h3>\n");
    match &v.comparison {
        None => out.push_str("<p class=\"muted\">No se comparó el contenido.</p>\n"),
        Some(c) => {
            let _ = writeln!(
                out,
                "<p>Comparados {} entradas, {} archivos, {}.</p>",
                c.entries,
                c.files,
                esc(&human_bytes(c.bytes))
            );
            if c.identical() {
                out.push_str("<p class=\"ok-text\"><strong>✓ Ninguna: lo restaurado es idéntico al origen.</strong></p>\n");
            } else {
                let _ = writeln!(
                    out,
                    "<p class=\"bad-text\"><strong>✗ {} diferencias.</strong></p><ul class=\"diffs\">",
                    c.total_differences
                );
                for d in &c.differences {
                    let _ = write!(out, "<li><code>{}</code></li>", esc(d));
                }
                out.push_str("</ul>\n");
                if c.total_differences > c.differences.len() {
                    let _ = writeln!(
                        out,
                        "<p class=\"muted\">… y {} más que no se listan.</p>",
                        c.total_differences - c.differences.len()
                    );
                }
            }
        }
    }
    out.push_str("</section>\n");
}

fn commands(out: &mut String, r: &Report) {
    out.push_str(
        "<section><h2>Comandos ejecutados</h2>\n\
         <p class=\"muted\">Exactamente lo que se ejecutó, en orden; se puede repetir a mano.</p>\n",
    );
    if r.commands.is_empty() {
        out.push_str("<p class=\"muted\">Ninguno.</p>\n");
    } else {
        out.push_str("<ol class=\"cmds\">\n");
        for c in &r.commands {
            let code = match c.exit_code {
                Some(0) => "<span class=\"ok-text\">salida 0</span>".to_string(),
                Some(n) => format!("<span class=\"bad-text\">salida {n}</span>"),
                None => "<span class=\"bad-text\">sin código (señal)</span>".to_string(),
            };
            let _ = writeln!(
                out,
                "<li><pre>{}</pre><span class=\"muted\">{code} · {} ms</span></li>",
                esc(&c.command),
                c.duration_ms
            );
        }
        out.push_str("</ol>\n");
    }
    out.push_str("</section>\n");
}

const CSS: &str = r#"
:root{--fg:#1b1f24;--muted:#5b636e;--bg:#fff;--line:#d7dce2;--ok:#11663a;--okbg:#e6f4ec;
--warn:#7a4d00;--warnbg:#fff4dc;--bad:#a1151d;--badbg:#fdeaea;--code:#f3f5f7}
@media (prefers-color-scheme:dark){:root{--fg:#e6e9ed;--muted:#9aa4b0;--bg:#14171a;--line:#333a42;
--ok:#6fd49b;--okbg:#0f2a1c;--warn:#f2c35b;--warnbg:#2e2410;--bad:#ff8a8f;--badbg:#341417;--code:#1f2429}}
*{box-sizing:border-box}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto}
h1{font-size:1.4rem;margin:0}h2{font-size:1.2rem;margin:0 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.25rem}
h3{font-size:1rem;margin:1rem 0 .4rem}
section{margin:0 0 1.5rem}
.verdict{display:flex;gap:1rem;align-items:center;padding:1rem;border:3px solid;border-radius:8px}
.verdict p{margin:.25rem 0 0}
.verdict .mark{font-size:2.5rem;font-weight:700;line-height:1;min-width:2.5rem;text-align:center}
.valid{color:var(--ok);background:var(--okbg);border-color:var(--ok)}
.reduced{color:var(--warn);background:var(--warnbg);border-color:var(--warn)}
.invalid{color:var(--bad);background:var(--badbg);border-color:var(--bad)}
.error{border-left:4px solid var(--bad);background:var(--badbg);padding:.5rem 1rem}
.ok-text{color:var(--ok)}.warn-text{color:var(--warn)}.bad-text{color:var(--bad)}
.muted{color:var(--muted)}
.meta{color:var(--muted);font-size:.9rem}
.tag{font-size:.75rem;border:1px solid currentColor;border-radius:4px;padding:0 .3rem}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;vertical-align:top;padding:.35rem .5rem;border-bottom:1px solid var(--line)}
table.kv th{width:32%;font-weight:600}
.scroll{overflow-x:auto}
code,pre{font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;font-size:.85em;
background:var(--code);border-radius:3px;padding:0 .2rem}
code,.detail{overflow-wrap:anywhere;word-break:break-word}
.detail{white-space:pre-wrap}
pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:.4rem;margin:0}
ul{margin:0;padding-left:1.2rem}
ol.cmds li{margin-bottom:.5rem}
@media (max-width:600px){body{font-size:15px;padding:12px}table.kv th{width:auto}
table.kv th,table.kv td{display:block;border:0;padding:.1rem 0}table.kv tr{display:block;
border-bottom:1px solid var(--line);padding:.3rem 0}}
@media print{:root{--fg:#000;--bg:#fff;--muted:#444;--code:#f3f3f3}body{padding:0;font-size:11pt}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}section{break-inside:auto}
tr,.verdict{break-inside:avoid}.scroll{overflow:visible}h2{break-after:avoid}}
"#;

/// Genera el HTML del informe.
pub fn render_html(r: &Report) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let verdict = match r.verdict() {
        Verdict::Valid => "válida",
        Verdict::Reduced => "reducida",
        Verdict::Invalid => "no válida",
    };
    let _ = write!(
        out,
        "<!DOCTYPE html>\n<html lang=\"es\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <title>Copia {verdict}: {}</title><style>{CSS}</style></head><body><main>\n",
        escp(&r.source)
    );
    out.push_str(&verdict_banner(r));
    let duration = (r.finished - r.started).num_seconds();
    let _ = writeln!(
        out,
        "<p class=\"meta\">{} {} · esquema v{} · inicio {} · fin {} ({} s)</p>",
        esc(r.tool),
        esc(r.version),
        r.schema_version,
        esc(&r.started.format("%Y-%m-%d %H:%M:%S %:z").to_string()),
        esc(&r.finished.format("%Y-%m-%d %H:%M:%S %:z").to_string()),
        duration
    );
    let sig = match &r.signature {
        Some(s) => format!(
            "Informe firmado ({}) con la clave pública <code>{}</code>. La firma cubre el JSON, \
             no este HTML: compruébala sobre el <code>.report.json</code>.",
            esc(&s.algo),
            esc(&s.public_key)
        ),
        None => "Informe sin firmar.".into(),
    };
    let _ = writeln!(out, "<p class=\"meta\">{sig}</p>");
    if let Some(e) = &r.error {
        let _ = writeln!(
            out,
            "<section class=\"error\"><h2>Error</h2><pre>{}</pre></section>",
            esc(e)
        );
    }
    if !r.warnings.is_empty() {
        out.push_str("<section><h2>Avisos</h2><ul>");
        for w in &r.warnings {
            let _ = write!(out, "<li>{}</li>", esc(w));
        }
        out.push_str("</ul></section>\n");
    }
    origin(&mut out, r);
    features(&mut out, r);
    modes(&mut out, r);
    chain(&mut out, r);
    verification(&mut out, r);
    commands(&mut out, r);
    out.push_str("</main></body></html>\n");
    out
}

/// Escribe el HTML del informe en `path`. Nunca sobrescribe.
pub fn write_html(report: &Report, path: &Path) -> Result<()> {
    super::atomic::write_new(path, render_html(report).as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample;
    use crate::types::{Verdict, Verification};

    #[test]
    fn shows_the_verdict_in_words() {
        let r = sample::report();
        let html = render_html(&r);
        assert!(html.contains("COPIA VÁLIDA"));
        assert!(html.contains("class=\"verdict valid\""));
        assert!(html.contains("lang=\"es\""));

        let mut bad = sample::report();
        bad.error = Some("falló".into());
        assert!(render_html(&bad).contains("COPIA NO VÁLIDA"));

        let mut reduced = sample::report();
        reduced.verification = Some(Verification {
            verdict: Verdict::Reduced,
            steps: vec![],
            comparison: None,
        });
        assert!(render_html(&reduced).contains("COMPROBACIÓN REDUCIDA"));
    }

    #[test]
    fn escapes_everything_from_the_report() {
        let html = render_html(&sample::report());
        // Ruta, detalle de un paso y comando con `<`, `&` y comillas.
        assert!(html.contains("/home/&lt;raro&gt; &amp; &quot;cía&quot;"));
        assert!(!html.contains("<raro>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("echo &#39;a&amp;b&#39;"));
    }

    #[test]
    fn is_self_contained() {
        let html = render_html(&sample::report());
        for needle in ["http://", "https://", "<link", "<script", "src="] {
            assert!(!html.contains(needle), "{needle}");
        }
    }

    #[test]
    fn has_every_section() {
        let html = render_html(&sample::report());
        for s in [
            "Origen",
            "Capas de bloque",
            "Features",
            "Modos de copia",
            "cadena de streams",
            "Verificación",
            "Diferencias encontradas",
            "Comandos ejecutados",
            "BLOCK_GROUP_TREE",
            "Partición",
            "no copiada",
        ] {
            assert!(html.contains(s), "{s}");
        }
    }

    #[test]
    fn never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.report.html");
        write_html(&sample::report(), &p).unwrap();
        assert!(write_html(&sample::report(), &p).is_err());
    }

    #[test]
    fn sizes_are_readable() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1,5 KiB (1536 B)");
    }
}
