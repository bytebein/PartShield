//! Interfaz gráfica de PartShield (GTK 4 + libadwaita).
//!
//! Primera versión, solo de lectura: lista los discos y, para un Btrfs,
//! muestra lo que detecta el motor (superbloque, features, modos seguros,
//! capas de bloque) y cada comando que ha ejecutado para saberlo.

mod model;

use std::path::PathBuf;

use adw::prelude::*;
use gtk::{gio, glib};
use partshield_core::cmd::CommandRecord;
use partshield_core::detect::devices::{human_size, Disk, Volume};
use partshield_core::detect::superblock::CopyStatus;
use partshield_core::types::{ChecksumStatus, LayerKind};

const APP_ID: &str = "io.partshield.PartShield";

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_window);
    // Los argumentos de la línea de órdenes no son para GTK.
    app.run_with_args::<&str>(&[])
}

fn build_window(app: &adw::Application) {
    let nav = adw::NavigationView::new();
    nav.add(&disks_page(app, &nav));
    // Para pruebas y capturas: abre directamente la detección de un dispositivo.
    if let Some(dev) = std::env::var_os("PARTSHIELD_GUI_OPEN") {
        let dev = PathBuf::from(dev);
        let label = dev
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        nav.push(&detect_page(app, dev, &label));
    }
    let win = adw::ApplicationWindow::builder()
        .application(app)
        .title("PartShield")
        .default_width(1100)
        .default_height(760)
        .content(&nav)
        .build();
    win.present();
    // Marca para las pruebas de arranque de la ISO (va al journal y a la consola).
    println!("PARTSHIELD_GUI_READY");
}

fn header(app: &adw::Application) -> adw::HeaderBar {
    let header = adw::HeaderBar::new();
    let quit = gtk::Button::with_label("Salir a la consola");
    quit.set_tooltip_text(Some("Cierra la interfaz y vuelve a la consola de texto"));
    let app = app.clone();
    quit.connect_clicked(move |_| app.quit());
    header.pack_end(&quit);
    header
}

// ------------------------------------------------------------------ discos

fn disks_page(app: &adw::Application, nav: &adw::NavigationView) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    let header = header(app);
    let refresh = gtk::Button::from_icon_name("view-refresh-symbolic");
    refresh.set_tooltip_text(Some("Volver a leer los discos"));
    header.pack_start(&refresh);
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&disks_content(app, nav)));
    {
        let (toolbar, app, nav) = (toolbar.clone(), app.clone(), nav.clone());
        refresh.connect_clicked(move |_| toolbar.set_content(Some(&disks_content(&app, &nav))));
    }
    adw::NavigationPage::builder()
        .title("Discos")
        .tag("discos")
        .child(&toolbar)
        .build()
}

fn disks_content(app: &adw::Application, nav: &adw::NavigationView) -> gtk::Widget {
    let (disks, commands) = match model::list_disks() {
        Ok(d) => d,
        Err(e) => return error_status("No se pudieron leer los discos", &format!("{e:#}")),
    };
    let page = adw::PreferencesPage::new();
    page.add(
        &adw::PreferencesGroup::builder()
            .title("Elige un sistema de archivos Btrfs")
            .description(
                "PartShield mostrará qué detecta y qué modos de copia son seguros. \
                 Esta pantalla solo lee: no escribe en ningún disco.",
            )
            .build(),
    );
    if disks.is_empty() {
        page.add(
            &adw::PreferencesGroup::builder()
                .description("No se ha encontrado ningún disco.")
                .build(),
        );
    }
    for disk in &disks {
        page.add(&disk_group(app, nav, disk));
    }
    page.add(&commands_group(&commands));
    page.upcast()
}

fn disk_group(
    app: &adw::Application,
    nav: &adw::NavigationView,
    disk: &Disk,
) -> adw::PreferencesGroup {
    let title = format!(
        "{} · {}",
        disk.model
            .as_deref()
            .unwrap_or(if disk.kind == "loop" { "Loop" } else { "Disco" }),
        human_size(disk.size)
    );
    let mut desc = vec![disk.path.display().to_string()];
    if let Some(t) = &disk.transport {
        desc.push(t.to_uppercase());
    }
    if let Some(s) = &disk.serial {
        desc.push(format!("n.º de serie {s}"));
    }
    if disk.removable {
        desc.push("extraíble".into());
    }
    if disk.volumes.iter().any(Volume::is_live_medium) {
        desc.push("USB de arranque de PartShield".into());
    }
    let group = adw::PreferencesGroup::builder()
        .title(glib::markup_escape_text(&title).as_str())
        .description(glib::markup_escape_text(&desc.join(" · ")).as_str())
        .build();
    if disk.volumes.is_empty() {
        let row = plain_row("Sin particiones ni sistema de archivos", "");
        row.add_css_class("dim-label");
        group.add(&row);
    }
    for v in &disk.volumes {
        group.add(&volume_row(app, nav, v));
    }
    group
}

fn volume_row(app: &adw::Application, nav: &adw::NavigationView, v: &Volume) -> adw::ActionRow {
    let name = v
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| v.path.display().to_string());
    let indent = "    ".repeat(v.depth);
    let mut sub = vec![human_size(v.size)];
    sub.push(match &v.fstype {
        Some(f) => f.clone(),
        None => "sin sistema de archivos".into(),
    });
    if let Some(l) = &v.label {
        sub.push(format!("«{l}»"));
    }
    if !v.mountpoints.is_empty() {
        sub.push(format!("montado en {}", v.mountpoints.join(", ")));
    }
    let row = plain_row(&format!("{indent}{name}"), &sub.join(" · "));
    let icon = match (v.fstype.as_deref(), v.kind.as_str()) {
        (Some("btrfs"), _) => "drive-harddisk-symbolic",
        (Some("crypto_LUKS"), _) | (_, "crypt") => "channel-secure-symbolic",
        (Some("vfat"), _) => "drive-removable-media-symbolic",
        _ => "drive-harddisk-symbolic",
    };
    row.add_prefix(&gtk::Image::from_icon_name(icon));
    if v.is_btrfs() {
        row.set_activatable(true);
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        let (app, nav, path, label) = (app.clone(), nav.clone(), v.path.clone(), name);
        row.connect_activated(move |_| nav.push(&detect_page(&app, path.clone(), &label)));
    } else {
        row.add_css_class("dim-label");
    }
    row
}

// --------------------------------------------------------------- detección

fn detect_page(app: &adw::Application, device: PathBuf, label: &str) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header(app));
    let spinner = gtk::Spinner::new();
    spinner.start();
    spinner.set_size_request(32, 32);
    toolbar.set_content(Some(
        &adw::StatusPage::builder()
            .title("Leyendo el superbloque…")
            .description(glib::markup_escape_text(&device.display().to_string()).as_str())
            .child(&spinner)
            .build(),
    ));

    let tb = toolbar.clone();
    glib::spawn_future_local(async move {
        let res = gio::spawn_blocking(move || model::detect(&device)).await;
        let w = match res {
            Ok(Ok(info)) => detect_view(&info),
            Ok(Err(e)) => error_status("No se pudo leer el Btrfs", &format!("{e:#}")),
            Err(_) => error_status(
                "La detección se interrumpió",
                "Error interno de PartShield.",
            ),
        };
        tb.set_content(Some(&w));
    });

    adw::NavigationPage::builder()
        .title(format!("Detección · {label}"))
        .child(&toolbar)
        .build()
}

fn detect_view(info: &model::DetectInfo) -> gtk::Widget {
    let sb = &info.superblock;
    let page = adw::PreferencesPage::new();

    let fs = group(
        "Sistema de archivos",
        Some(&info.device.display().to_string()),
    );
    fs.add(&info_row(
        "Etiqueta",
        if sb.label.is_empty() {
            "(sin etiqueta)"
        } else {
            &sb.label
        },
    ));
    fs.add(&info_row("UUID", &sb.fsid));
    fs.add(&info_row(
        "Tamaño",
        &format!(
            "{} ({} usados)",
            human_size(sb.total_bytes),
            human_size(sb.bytes_used)
        ),
    ));
    fs.add(&info_row("Dispositivos", &sb.num_devices.to_string()));
    fs.add(&info_row(
        "Checksum del superbloque",
        &match &sb.checksum {
            ChecksumStatus::Valid => "verificado".to_string(),
            ChecksumStatus::NotVerified { csum_type } => format!("tipo {csum_type}, no verificado"),
        },
    ));
    page.add(&fs);

    let copies = group(
        "Copias del superbloque",
        Some("Btrfs guarda copias en 64 KiB, 64 MiB y 256 GiB; se comprueba que coinciden."),
    );
    for c in &info.copies.copies {
        let (state, ok) = match &c.status {
            CopyStatus::Valid { superblock } => (
                format!("válida, generación {}", superblock.generation),
                true,
            ),
            CopyStatus::Absent => ("no existe (el dispositivo es más pequeño)".into(), true),
            CopyStatus::Invalid { error } => (format!("NO VÁLIDA: {error}"), false),
        };
        copies.add(&status_row(
            &format!("Copia {} · byte {}", c.index, c.offset),
            &state,
            ok,
        ));
    }
    page.add(&copies);

    let features = group(
        "Características (features)",
        Some("Las que activó mkfs.btrfs o se añadieron después. Deciden qué modos de copia son seguros."),
    );
    features.add(&info_row(
        "compat_ro",
        &names_or_none(sb.features.compat_ro.names()),
    ));
    features.add(&info_row(
        "incompat",
        &names_or_none(sb.features.incompat.names()),
    ));
    let unknown = sb.features.compat_ro.unknown() | sb.features.incompat.unknown();
    if unknown != 0 || sb.features.compat != 0 {
        features.add(&status_row(
            "Bits desconocidos",
            &format!("{unknown:#x}: esta versión de PartShield no los conoce"),
            false,
        ));
    }
    page.add(&features);

    let modes = group(
        "Modos de copia",
        Some("Si un modo no es seguro para este Btrfs, se explica por qué."),
    );
    for a in &info.modes {
        let name = format!("{:?}", a.mode).to_lowercase();
        let detail = if a.allowed {
            "Permitido".to_string()
        } else {
            a.reasons.join("; ")
        };
        modes.add(&status_row(&name, &detail, a.allowed));
    }
    page.add(&modes);

    let layers = group(
        "Capas de bloque",
        Some("Del dispositivo con el Btrfs hacia el disco físico."),
    );
    match &info.stack {
        Ok(stack) if !stack.layers.is_empty() => {
            for l in &stack.layers {
                let kind = match l.kind {
                    LayerKind::Disk => "disco",
                    LayerKind::Partition => "partición",
                    LayerKind::Luks => "LUKS",
                    LayerKind::LvmLv => "volumen LVM",
                    LayerKind::Loop => "loop",
                    LayerKind::Other => "otro",
                };
                let mut d = vec![kind.to_string()];
                if let Some(u) = &l.uuid {
                    d.push(u.clone());
                }
                if let Some(x) = &l.detail {
                    d.push(x.clone());
                }
                layers.add(&info_row(&l.device.display().to_string(), &d.join(" · ")));
            }
        }
        Ok(_) => layers.add(&info_row(
            "Sin capas",
            "el Btrfs está directamente en el dispositivo",
        )),
        Err(e) => layers.add(&status_row("No se pudieron leer", e, false)),
    }
    page.add(&layers);

    if !info.warnings.is_empty() {
        let warn = group("Avisos", None);
        for w in &info.warnings {
            warn.add(&status_row("Aviso", w, false));
        }
        page.add(&warn);
    }

    let next = group("Siguiente paso", None);
    let copy = plain_row(
        "Copiar este sistema de archivos",
        &format!(
            "Llegará en la próxima versión de la interfaz. Mientras, desde la consola: \
             sudo partshield backup <subvolumen montado> --dest <carpeta> (Btrfs en {})",
            info.device.display()
        ),
    );
    copy.set_sensitive(false);
    next.add(&copy);
    page.add(&next);

    page.add(&commands_group(&info.commands));
    page.upcast()
}

// ---------------------------------------------------------------- piezas

/// Fila de texto plano. El marcado se desactiva antes de poner el texto:
/// rutas, comandos y etiquetas pueden contener `<` o `&`.
fn plain_row(title: &str, subtitle: &str) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_use_markup(false);
    row.set_title(title);
    if !subtitle.is_empty() {
        row.set_subtitle(subtitle);
    }
    row
}

fn group(title: &str, description: Option<&str>) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::builder()
        .title(glib::markup_escape_text(title).as_str())
        .build();
    if let Some(d) = description {
        g.set_description(Some(glib::markup_escape_text(d).as_str()));
    }
    g
}

fn info_row(title: &str, value: &str) -> adw::ActionRow {
    let row = plain_row(title, value);
    row.set_subtitle_selectable(true);
    row.add_css_class("property");
    row
}

fn status_row(title: &str, detail: &str, ok: bool) -> adw::ActionRow {
    let row = plain_row(title, detail);
    row.set_subtitle_selectable(true);
    let icon = gtk::Image::from_icon_name(if ok {
        "emblem-ok-symbolic"
    } else {
        "dialog-warning-symbolic"
    });
    icon.add_css_class(if ok { "success" } else { "warning" });
    row.add_prefix(&icon);
    row
}

/// Cada herramienta externa que se ejecutó, como en el informe.
fn commands_group(commands: &[CommandRecord]) -> adw::PreferencesGroup {
    let g = group(
        "Comandos ejecutados",
        Some("PartShield muestra todo lo que lanza para que puedas repetirlo a mano."),
    );
    let exp = adw::ExpanderRow::new();
    exp.set_use_markup(false);
    exp.set_title(&format!("{} comando(s)", commands.len()));
    for c in commands {
        let code = match c.exit_code {
            Some(0) => "ok".to_string(),
            Some(n) => format!("salió con {n}"),
            None => "interrumpido".to_string(),
        };
        let row = plain_row(&c.command, &format!("{code} · {} ms", c.duration_ms));
        row.set_title_selectable(true);
        row.add_css_class("monospace");
        exp.add_row(&row);
    }
    g.add(&exp);
    g
}

fn error_status(title: &str, detail: &str) -> gtk::Widget {
    adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title(title)
        .description(glib::markup_escape_text(detail).as_str())
        .build()
        .upcast()
}

fn names_or_none(names: Vec<&str>) -> String {
    if names.is_empty() {
        "ninguna".into()
    } else {
        names.join(", ")
    }
}
