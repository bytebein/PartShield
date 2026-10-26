//! Interfaz gráfica de PartShield (GTK 4 + libadwaita).
//!
//! Discos → detección de un Btrfs (superbloque, features, modos seguros,
//! capas de bloque) → copia con destino en otro disco → verificación y
//! veredicto. Cada pantalla enseña los comandos que ha ejecutado.

mod model;

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gio, glib};
use partshield_core::cmd::CommandRecord;
use partshield_core::detect::devices::{human_size, Disk, Volume};
use partshield_core::detect::superblock::CopyStatus;
use partshield_core::types::{
    ChecksumStatus, HashAlgo, LayerKind, Mode, Report, StepStatus, Verdict,
};

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
        nav.push(&detect_page(app, &nav, dev, &label));
    }
    let win = adw::ApplicationWindow::builder()
        .application(app)
        .title("PartShield")
        .default_width(1100)
        .default_height(760)
        .content(&nav)
        .build();
    // Para capturas: PARTSHIELD_GUI_SIZE=1100x1600.
    if let Some((w, h)) = std::env::var("PARTSHIELD_GUI_SIZE")
        .ok()
        .and_then(|v| v.split_once('x').map(|(w, h)| (w.parse(), h.parse())))
        .and_then(|(w, h)| Some((w.ok()?, h.ok()?)))
    {
        win.set_default_size(w, h);
    }
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
        row.connect_activated(move |_| nav.push(&detect_page(&app, &nav, path.clone(), &label)));
    } else {
        row.add_css_class("dim-label");
    }
    row
}

// --------------------------------------------------------------- detección

fn detect_page(
    app: &adw::Application,
    nav: &adw::NavigationView,
    device: PathBuf,
    label: &str,
) -> adw::NavigationPage {
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

    let (tb, app, nav) = (toolbar.clone(), app.clone(), nav.clone());
    glib::spawn_future_local(async move {
        let res = gio::spawn_blocking(move || model::detect(&device)).await;
        let w = match res {
            Ok(Ok(info)) => {
                // Para pruebas y capturas: sigue directamente a la copia.
                if std::env::var_os("PARTSHIELD_GUI_COPY").is_some() {
                    nav.push(&copy_page(&app, &nav, Rc::new(CopySource::from(&info))));
                }
                detect_view(&app, &nav, &info)
            }
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

fn detect_view(
    app: &adw::Application,
    nav: &adw::NavigationView,
    info: &model::DetectInfo,
) -> gtk::Widget {
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
    let src = Rc::new(CopySource::from(info));
    let copy = plain_row(
        "Copiar este sistema de archivos",
        "Eliges qué copiar y dónde; después se restaura la copia y se compara con el original.",
    );
    copy.add_prefix(&gtk::Image::from_icon_name("document-save-symbolic"));
    copy.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    copy.set_activatable(true);
    {
        let (app, nav) = (app.clone(), nav.clone());
        copy.connect_activated(move |_| nav.push(&copy_page(&app, &nav, src.clone())));
    }
    next.add(&copy);
    page.add(&next);

    page.add(&commands_group(&info.commands));
    page.upcast()
}

// ------------------------------------------------------------------- copia

/// Lo que la pantalla de copia necesita saber del Btrfs detectado.
struct CopySource {
    device: PathBuf,
    fsid: String,
    label: String,
    bytes_used: u64,
    /// `None` si el modo es seguro; si no, por qué no.
    send_blocked: Option<String>,
    raw_blocked: Option<String>,
}

impl From<&model::DetectInfo> for CopySource {
    fn from(info: &model::DetectInfo) -> Self {
        let blocked = |mode: Mode| {
            info.modes
                .iter()
                .find(|a| a.mode == mode)
                .and_then(|a| (!a.allowed).then(|| a.reasons.join("; ")))
        };
        Self {
            device: info.device.clone(),
            fsid: info.superblock.fsid.clone(),
            label: info
                .device
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            bytes_used: info.superblock.bytes_used,
            send_blocked: blocked(Mode::Send),
            raw_blocked: blocked(Mode::Raw),
        }
    }
}

/// Estado de la pantalla de copia, compartido entre sus controles.
#[derive(Default)]
struct CopyForm {
    mount: Option<PathBuf>,
    /// (ruta del subvolumen, interruptor)
    subvolumes: Vec<(String, adw::SwitchRow)>,
    destinations: Vec<model::Destination>,
}

/// Posición de «Imagen completa» en el desplegable de modo (0 es send).
const MODE_RAW: u32 = 1;

fn copy_page(
    app: &adw::Application,
    nav: &adw::NavigationView,
    src: Rc<CopySource>,
) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header(app));
    let page = adw::PreferencesPage::new();
    let form = Rc::new(RefCell::new(CopyForm::default()));

    // ---- qué copiar
    let what = group(
        "Qué copiar",
        Some(&format!(
            "{} · {} usados",
            src.device.display(),
            human_size(src.bytes_used)
        )),
    );
    let modes = gtk::StringList::new(&[
        "Subvolúmenes (btrfs send)",
        "Imagen completa, sector a sector",
    ]);
    let mode = adw::ComboRow::builder().title("Modo").model(&modes).build();
    let mode_help = plain_row("", "");
    mode_help.add_css_class("dim-label");
    what.add(&mode);
    what.add(&mode_help);
    page.add(&what);

    let subs = group(
        "Subvolúmenes",
        Some(
            "Los snapshots (snapper, timeshift) no se marcan solos. Para crear los \
              snapshots temporales de la copia, el origen se monta en escritura un momento; \
              tus archivos no se tocan.",
        ),
    );
    let subs_status = plain_row("Montando el origen en solo lectura…", "");
    subs.add(&subs_status);
    page.add(&subs);

    // ---- destino
    let dest = group(
        "Destino",
        Some(
            "Solo se ofrecen otros discos: nunca el que se copia ni el USB de PartShield. \
              Se crea la carpeta partshield-copias y no se borra nada.",
        ),
    );
    let dest_list = gtk::StringList::new(&[]);
    let dest_row = adw::ComboRow::builder()
        .title("Guardar en")
        .model(&dest_list)
        .build();
    let dest_info = plain_row("", "");
    dest_info.add_css_class("dim-label");
    let other = plain_row(
        "Otra carpeta…",
        "Un NAS o un disco que ya hayas montado a mano",
    );
    other.set_activatable(true);
    other.add_suffix(&gtk::Image::from_icon_name("folder-open-symbolic"));
    dest.add(&dest_row);
    dest.add(&dest_info);
    dest.add(&other);
    page.add(&dest);

    match model::list_disks() {
        Ok((disks, _)) => {
            let found = model::destinations(&disks, &src.device);
            for d in &found {
                dest_list.append(&format!("{} · {} · {}", d.title(), d.fstype, d.disk));
            }
            form.borrow_mut().destinations = found;
        }
        Err(e) => dest_info.set_subtitle(&format!("No se pudieron leer los discos: {e:#}")),
    }

    // ---- avanzadas
    let adv = group("Opciones avanzadas", None);
    let exp = adw::ExpanderRow::builder()
        .title("Compresión, hash e incrementales")
        .build();
    let zstd = adw::SpinRow::with_range(1.0, 19.0, 1.0);
    zstd.set_title("Nivel de zstd");
    zstd.set_subtitle("3 es rápido; 19 ocupa menos y tarda mucho más");
    zstd.set_value(3.0);
    let hashes = gtk::StringList::new(&["BLAKE3", "SHA-256"]);
    let hash = adw::ComboRow::builder()
        .title("Hash de los streams")
        .model(&hashes)
        .build();
    let layout = adw::SwitchRow::builder()
        .title("Guardar tabla de particiones, ESP y UUID")
        .subtitle("Para poder restaurar en un disco vacío y que arranque")
        .active(true)
        .build();
    let keep = adw::SwitchRow::builder()
        .title("Conservar el snapshot en el origen")
        .subtitle("Necesario para que la próxima copia sea incremental")
        .build();
    exp.add_row(&zstd);
    exp.add_row(&hash);
    exp.add_row(&layout);
    exp.add_row(&keep);
    adv.add(&exp);
    page.add(&adv);

    // ---- botón
    let go = gtk::Button::builder()
        .label("Copiar y verificar")
        .halign(gtk::Align::Center)
        .margin_top(12)
        .build();
    go.add_css_class("pill");
    go.add_css_class("suggested-action");
    let go_note = gtk::Label::new(None);
    go_note.add_css_class("dim-label");
    go_note.set_wrap(true);
    let bottom = gtk::Box::new(gtk::Orientation::Vertical, 6);
    bottom.append(&go);
    bottom.append(&go_note);
    let bottom_group = adw::PreferencesGroup::new();
    bottom_group.add(&bottom);
    page.add(&bottom_group);

    // Activa el botón solo cuando hay algo que copiar y un destino.
    let refresh: Rc<dyn Fn()> = {
        let (form, mode, dest_row, go, go_note, src, dest_info) = (
            form.clone(),
            mode.clone(),
            dest_row.clone(),
            go.clone(),
            go_note.clone(),
            src.clone(),
            dest_info.clone(),
        );
        Rc::new(move || {
            let f = form.borrow();
            let raw = mode.selected() == MODE_RAW;
            let blocked = if raw {
                &src.raw_blocked
            } else {
                &src.send_blocked
            };
            let dest = f.destinations.get(dest_row.selected() as usize);
            let problem = if let Some(why) = blocked {
                Some(format!("Este modo no es seguro aquí: {why}"))
            } else if dest.is_none() {
                Some("Elige un destino.".to_string())
            } else if !raw && f.mount.is_none() {
                Some("Esperando a leer los subvolúmenes…".to_string())
            } else if !raw && !f.subvolumes.iter().any(|(_, sw)| sw.is_active()) {
                Some("Marca al menos un subvolumen.".to_string())
            } else {
                None
            };
            go.set_sensitive(problem.is_none());
            go_note.set_text(problem.as_deref().unwrap_or(""));
            if let Some(d) = dest {
                let free = d
                    .mountpoint
                    .as_deref()
                    .and_then(model::free_bytes)
                    .map(|b| format!("{} libres", human_size(b)))
                    .unwrap_or_else(|| "se montará al empezar".into());
                dest_info.set_title(&d.device.display().to_string());
                dest_info.set_subtitle(&format!(
                    "{} · {} · {free}. Hace falta sitio para la copia y para \
                     restaurarla al verificarla (hasta unas {} en total).",
                    d.fstype,
                    human_size(d.size),
                    // Stream comprimido + restauración temporal + margen.
                    human_size(src.bytes_used.saturating_mul(2) + (256 << 20))
                ));
            }
        })
    };

    {
        let (subs, mode_help, src, refresh) = (
            subs.clone(),
            mode_help.clone(),
            src.clone(),
            refresh.clone(),
        );
        let on_mode = move |m: &adw::ComboRow| {
            let raw = m.selected() == MODE_RAW;
            subs.set_visible(!raw);
            mode_help.set_title(if raw {
                "Copia cada sector del dispositivo, también el espacio libre"
            } else {
                "Solo los datos, subvolumen a subvolumen; permite incrementales"
            });
            let blocked = if raw {
                &src.raw_blocked
            } else {
                &src.send_blocked
            };
            mode_help.set_subtitle(blocked.as_deref().unwrap_or(if raw {
                "No escribe nada en el origen. Ocupa lo que ocupe el dispositivo (comprimido)."
            } else {
                "El modo recomendado para Btrfs."
            }));
            refresh();
        };
        on_mode(&mode);
        mode.connect_selected_notify(on_mode);
    }
    if src.send_blocked.is_some() && src.raw_blocked.is_none() {
        mode.set_selected(MODE_RAW);
    }
    {
        let refresh = refresh.clone();
        dest_row.connect_selected_notify(move |_| refresh());
    }
    {
        let (form, dest_list, dest_row, refresh) = (
            form.clone(),
            dest_list.clone(),
            dest_row.clone(),
            refresh.clone(),
        );
        other.connect_activated(move |row| {
            let dialog = gtk::FileDialog::builder()
                .title("Carpeta donde guardar la copia")
                .modal(true)
                .build();
            let win = row.root().and_downcast::<gtk::Window>();
            let (form, dest_list, dest_row, refresh) = (
                form.clone(),
                dest_list.clone(),
                dest_row.clone(),
                refresh.clone(),
            );
            dialog.select_folder(win.as_ref(), gio::Cancellable::NONE, move |res| {
                let Some(path) = res.ok().and_then(|f| f.path()) else {
                    return;
                };
                let d = model::Destination {
                    device: path.clone(),
                    disk: "carpeta".into(),
                    fstype: "carpeta".into(),
                    label: None,
                    size: 0,
                    mountpoint: Some(path.clone()),
                };
                dest_list.append(&path.display().to_string());
                form.borrow_mut().destinations.push(d);
                dest_row.set_selected(dest_list.n_items() - 1);
                refresh();
            });
        });
    }

    // Monta el origen y lista los subvolúmenes sin bloquear la ventana.
    {
        let (form, subs, subs_status, refresh, src2) = (
            form.clone(),
            subs.clone(),
            subs_status.clone(),
            refresh.clone(),
            src.clone(),
        );
        glib::spawn_future_local(async move {
            let (dev, fsid) = (src2.device.clone(), src2.fsid.clone());
            let res = gio::spawn_blocking(move || model::mount_source(&dev, &fsid)).await;
            match res {
                Ok(Ok(m)) => {
                    subs.remove(&subs_status);
                    let mut rows = Vec::new();
                    let top = adw::SwitchRow::builder()
                        .title("Nivel superior")
                        .subtitle(if m.subvolumes.is_empty() {
                            "Este Btrfs no tiene subvolúmenes: se copia entero"
                        } else {
                            "Solo archivos sueltos fuera de los subvolúmenes"
                        })
                        .active(m.subvolumes.is_empty())
                        .build();
                    rows.push((String::new(), top));
                    for sv in &m.subvolumes {
                        let row = adw::SwitchRow::new();
                        row.set_use_markup(false);
                        row.set_title(&sv.path);
                        row.set_subtitle(&format!(
                            "id {}{}",
                            sv.id,
                            if sv.looks_like_snapshot() {
                                " · parece un snapshot"
                            } else if sv.top_level != 5 {
                                " · anidado"
                            } else {
                                ""
                            }
                        ));
                        row.set_active(sv.selected_by_default());
                        rows.push((sv.path.clone(), row));
                    }
                    for (_, row) in &rows {
                        subs.add(row);
                        let refresh = refresh.clone();
                        row.connect_active_notify(move |_| refresh());
                    }
                    let mut f = form.borrow_mut();
                    f.mount = Some(m.mountpoint);
                    f.subvolumes = rows;
                }
                Ok(Err(e)) => {
                    subs_status.set_title("No se pudo montar el origen");
                    subs_status.set_subtitle(&format!("{e:#}"));
                }
                Err(_) => subs_status.set_title("Error interno al montar el origen"),
            }
            refresh();
        });
    }

    {
        let (app, nav, form, src) = (app.clone(), nav.clone(), form.clone(), src.clone());
        let (mode, dest_row, zstd, hash, layout, keep) = (
            mode.clone(),
            dest_row.clone(),
            zstd.clone(),
            hash.clone(),
            layout.clone(),
            keep.clone(),
        );
        go.connect_clicked(move |_| {
            let f = form.borrow();
            let Some(dest) = f.destinations.get(dest_row.selected() as usize).cloned() else {
                return;
            };
            let job = if mode.selected() == MODE_RAW {
                model::Job::Raw {
                    device: src.device.clone(),
                }
            } else {
                let Some(mount) = f.mount.clone() else { return };
                model::Job::Send {
                    mount,
                    subvolumes: f
                        .subvolumes
                        .iter()
                        .filter(|(_, sw)| sw.is_active())
                        .map(|(p, _)| p.clone())
                        .collect(),
                    layout: layout.is_active(),
                    keep_snapshot: keep.is_active(),
                }
            };
            let opts = model::JobOptions {
                dest,
                zstd_level: zstd.value() as i32,
                hash: if hash.selected() == 1 {
                    HashAlgo::Sha256
                } else {
                    HashAlgo::Blake3
                },
            };
            nav.push(&progress_page(&app, &nav, &src.label, job, opts));
        });
    }

    toolbar.set_content(Some(&page));
    adw::NavigationPage::builder()
        .title(format!("Copiar · {}", src.label))
        .child(&toolbar)
        .build()
}

fn progress_page(
    app: &adw::Application,
    nav: &adw::NavigationView,
    label: &str,
    job: model::Job,
    opts: model::JobOptions,
) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header(app));
    let page = adw::NavigationPage::builder()
        .title(format!("Copiando · {label}"))
        .child(&toolbar)
        .can_pop(false)
        .build();

    let spinner = gtk::Spinner::new();
    spinner.start();
    spinner.set_size_request(32, 32);
    let elapsed = gtk::Label::new(Some("0:00"));
    elapsed.add_css_class("numeric");
    let log = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(8)
        .right_margin(8)
        .build();
    let scroll = gtk::ScrolledWindow::builder()
        .child(&log)
        .vexpand(true)
        .min_content_height(240)
        .build();
    scroll.add_css_class("card");
    let col = gtk::Box::new(gtk::Orientation::Vertical, 12);
    col.append(&spinner);
    col.append(&elapsed);
    col.append(&scroll);
    let status = adw::StatusPage::builder()
        .title("Copiando y verificando…")
        .description(
            "Primero se hace la copia; después se restaura en un espacio temporal, \
             se comprueba, se monta y se compara con el original. No apagues el equipo.",
        )
        .child(&adw::Clamp::builder().maximum_size(900).child(&col).build())
        .vexpand(true)
        .build();
    toolbar.set_content(Some(&status));

    let (tx, rx) = mpsc::channel::<String>();
    let done = Rc::new(Cell::new(false));
    let start = Instant::now();
    {
        let (done, log, scroll, elapsed) =
            (done.clone(), log.clone(), scroll.clone(), elapsed.clone());
        glib::timeout_add_local(Duration::from_millis(300), move || {
            let buf = log.buffer();
            let mut added = false;
            while let Ok(line) = rx.try_recv() {
                buf.insert(&mut buf.end_iter(), &format!("$ {line}\n"));
                added = true;
            }
            if added {
                let adj = scroll.vadjustment();
                adj.set_value(adj.upper());
            }
            let secs = start.elapsed().as_secs();
            elapsed.set_text(&format!("{}:{:02}", secs / 60, secs % 60));
            if done.get() {
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });
    }
    {
        let (tb, nav, page2, app) = (toolbar.clone(), nav.clone(), page.clone(), app.clone());
        glib::spawn_future_local(async move {
            let res = gio::spawn_blocking(move || model::run_job(&job, &opts, tx)).await;
            done.set(true);
            let w = match res {
                Ok(Ok((report, path))) => result_view(&nav, &report, &path),
                Ok(Err(e)) => error_status("No se pudo hacer la copia", &format!("{e:#}")),
                Err(_) => error_status("La copia se interrumpió", "Error interno de PartShield."),
            };
            tb.set_content(Some(&w));
            page2.set_can_pop(true);
            let _ = app;
        });
    }
    page
}

fn result_view(nav: &adw::NavigationView, report: &Report, path: &std::path::Path) -> gtk::Widget {
    let page = adw::PreferencesPage::new();
    let (icon, title, css, desc) = match (report.verdict(), &report.error) {
        (_, Some(e)) => (
            "dialog-error-symbolic",
            "La copia NO es válida",
            "error",
            format!("Falló: {e}"),
        ),
        (Verdict::Valid, _) => (
            "emblem-ok-symbolic",
            "Copia válida",
            "success",
            "Se ha restaurado, montado y comparado con el original sin diferencias.".to_string(),
        ),
        (Verdict::Reduced, _) => (
            "dialog-warning-symbolic",
            "Copia válida, con pasos omitidos",
            "warning",
            "No falló nada, pero algún paso de la verificación no se pudo hacer.".to_string(),
        ),
        (Verdict::Invalid, _) => (
            "dialog-error-symbolic",
            "La copia NO es válida",
            "error",
            "La verificación encontró un problema: no confíes en esta copia.".to_string(),
        ),
    };
    let head = adw::StatusPage::builder()
        .icon_name(icon)
        .title(title)
        .description(glib::markup_escape_text(&desc).as_str())
        .build();
    head.add_css_class(css);
    head.add_css_class("compact");
    let head_group = adw::PreferencesGroup::new();
    head_group.add(&head);
    page.add(&head_group);

    if let Some(v) = &report.verification {
        let steps = group("Verificación", None);
        for st in &v.steps {
            let (ok, word) = match st.status {
                StepStatus::Passed => (true, "superado"),
                StepStatus::Failed => (false, "FALLÓ"),
                StepStatus::Skipped => (false, "omitido"),
            };
            let detail = if st.detail.is_empty() {
                word.to_string()
            } else {
                format!("{word} · {}", st.detail)
            };
            steps.add(&status_row(st.name, &detail, ok));
        }
        page.add(&steps);
    }
    if !report.warnings.is_empty() {
        let warn = group("Avisos", None);
        for w in &report.warnings {
            warn.add(&status_row("Aviso", w, false));
        }
        page.add(&warn);
    }

    let files = group(
        "Informe",
        Some("Guárdalo junto a la copia: con él se restaura y se vuelve a verificar."),
    );
    files.add(&info_row("JSON", &path.display().to_string()));
    files.add(&info_row(
        "HTML",
        &path.with_extension("html").display().to_string(),
    ));
    let secs = (report.finished - report.started).num_seconds().max(0);
    files.add(&info_row(
        "Duración",
        &format!("{}:{:02}", secs / 60, secs % 60),
    ));
    page.add(&files);

    let back = gtk::Button::builder()
        .label("Volver a los discos")
        .halign(gtk::Align::Center)
        .build();
    back.add_css_class("pill");
    {
        let nav = nav.clone();
        back.connect_clicked(move |_| {
            nav.pop_to_tag("discos");
        });
    }
    let g = adw::PreferencesGroup::new();
    g.add(&back);
    page.add(&g);

    page.add(&commands_group(&report.commands));
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
