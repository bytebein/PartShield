//! Modo sencillo: inicio con dos botones, copia en tres pasos (qué, dónde,
//! empezar) y una barra de progreso. Lo técnico queda en el modo avanzado.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gio, glib};
use partshield_core::detect::devices::{human_size, Disk, Volume};
use partshield_core::types::{Report, Verdict};

use crate::model::{self, Destination, PlanEvent, PlanItem};
use crate::{disks_page, error_status, group, header, plain_row, result_view};

pub const CSS: &str = "
.hero-title { font-size: 2.4em; font-weight: 800; }
.action-card { padding: 28px 24px; }
.action-card .card-title { font-size: 1.35em; font-weight: 700; }
.action-card.primary { background-color: @accent_bg_color; color: @accent_fg_color; }
.action-card.primary:hover { background-image: image(alpha(currentColor, 0.08)); }
.action-card.primary .dim-label { opacity: 0.85; }
.step-title { font-size: 1.1em; font-weight: 700; }
.verdict-ok { color: @success_color; }
.verdict-warn { color: @warning_color; }
.verdict-bad { color: @error_color; }
";

// ------------------------------------------------------------------ inicio

pub fn home_page(app: &adw::Application, nav: &adw::NavigationView) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    let head = header(app);
    head.pack_start(&tools_button());
    let advanced = gtk::Switch::builder().valign(gtk::Align::Center).build();
    let adv_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    adv_box.append(&gtk::Label::new(Some("Avanzado")));
    adv_box.append(&advanced);
    adv_box.set_tooltip_text(Some(
        "Muestra todo: superbloque, modos de copia, subvolúmenes y comandos",
    ));
    head.pack_end(&adv_box);
    toolbar.add_top_bar(&head);

    let icon = gtk::Image::from_icon_name("drive-harddisk-symbolic");
    icon.set_pixel_size(72);
    icon.add_css_class("accent");
    let title = gtk::Label::new(Some("PartShield"));
    title.add_css_class("hero-title");
    let tagline = gtk::Label::new(Some(
        "Copias de seguridad que se restauran y se comprueban antes de darlas por buenas.",
    ));
    tagline.add_css_class("dim-label");
    tagline.set_wrap(true);
    tagline.set_justify(gtk::Justification::Center);

    let backup = action_card(
        "document-save-symbolic",
        "Hacer copia",
        "Elige el disco o las particiones y dónde guardarlas",
    );
    backup.add_css_class("primary");
    let restore = action_card(
        "document-revert-symbolic",
        "Restaurar",
        "Muy pronto. De momento, desde la consola: partshield restore",
    );
    restore.set_sensitive(false);
    let cards = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(18)
        .homogeneous(true)
        .margin_top(24)
        .build();
    cards.append(&backup);
    cards.append(&restore);

    let col = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .valign(gtk::Align::Center)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    col.append(&icon);
    col.append(&title);
    col.append(&tagline);
    col.append(&cards);
    let clamp = adw::Clamp::builder().maximum_size(720).child(&col).build();
    toolbar.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .child(&clamp)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build(),
    ));

    {
        let (app, nav, advanced) = (app.clone(), nav.clone(), advanced.clone());
        backup.connect_clicked(move |_| {
            if advanced.is_active() {
                nav.push(&disks_page(&app, &nav));
            } else {
                nav.push(&copy_page(&app, &nav));
            }
        });
    }
    adw::NavigationPage::builder()
        .title("PartShield")
        .tag("inicio")
        .child(&toolbar)
        .build()
}

fn action_card(icon: &str, title: &str, text: &str) -> gtk::Button {
    let img = gtk::Image::from_icon_name(icon);
    img.set_pixel_size(48);
    let t = gtk::Label::new(Some(title));
    t.add_css_class("card-title");
    let d = gtk::Label::new(Some(text));
    d.set_wrap(true);
    d.set_justify(gtk::Justification::Center);
    d.set_max_width_chars(28);
    d.add_css_class("dim-label");
    let b = gtk::Box::new(gtk::Orientation::Vertical, 10);
    b.append(&img);
    b.append(&t);
    b.append(&d);
    let button = gtk::Button::builder().child(&b).build();
    button.add_css_class("card");
    button.add_css_class("action-card");
    button
}

/// Menú «Herramientas». GParted solo si está instalado.
fn tools_button() -> gtk::MenuButton {
    let list = gtk::Box::new(gtk::Orientation::Vertical, 4);
    list.set_margin_top(6);
    list.set_margin_bottom(6);
    let gparted = ["/usr/sbin/gparted", "/usr/bin/gparted"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists());
    let item = gtk::Button::builder()
        .child(
            &adw::ButtonContent::builder()
                .icon_name("drive-multidisk-symbolic")
                .label("GParted: particiones")
                .build(),
        )
        .build();
    item.add_css_class("flat");
    match gparted {
        Some(path) => {
            item.set_tooltip_text(Some("Crear, borrar o formatear particiones"));
            item.connect_clicked(move |_| {
                let _ = std::process::Command::new(&path).spawn();
            });
        }
        None => {
            item.set_sensitive(false);
            item.set_tooltip_text(Some("No está en esta versión de la ISO"));
        }
    }
    list.append(&item);
    let pop = gtk::Popover::builder().child(&list).build();
    gtk::MenuButton::builder()
        .label("Herramientas")
        .popover(&pop)
        .build()
}

// ------------------------------------------------------------------- copia

/// Un disco con su casilla y las de sus particiones.
struct DiskPick {
    disk: Disk,
    check: gtk::CheckButton,
    parts: Vec<(Volume, gtk::CheckButton)>,
}

impl DiskPick {
    fn chosen(&self) -> impl Iterator<Item = &Volume> {
        self.parts
            .iter()
            .filter(|(_, c)| c.is_active())
            .map(|(v, _)| v)
    }

    /// Entero = marcadas todas las que se marcan con el disco.
    fn whole(&self) -> bool {
        self.parts.iter().any(|(_, c)| c.is_active())
            && self
                .parts
                .iter()
                .all(|(v, c)| c.is_active() || !model::checked_with_disk(v))
    }
}

#[derive(Default)]
struct Form {
    disks: Vec<Disk>,
    picks: Vec<DiskPick>,
    dests: Vec<(Destination, gtk::CheckButton)>,
    dest_rows: Vec<adw::ActionRow>,
    radio_anchor: Option<gtk::CheckButton>,
}

impl Form {
    fn items(&self) -> Vec<PlanItem> {
        self.picks
            .iter()
            .flat_map(|p| p.chosen().map(PlanItem::new))
            .collect()
    }

    fn sources(&self) -> Vec<PathBuf> {
        self.picks
            .iter()
            .filter(|p| p.chosen().next().is_some())
            .map(|p| p.disk.path.clone())
            .collect()
    }

    fn dest(&self) -> Option<&Destination> {
        self.dests
            .iter()
            .find(|(_, c)| c.is_active())
            .map(|(d, _)| d)
    }
}

pub fn copy_page(app: &adw::Application, nav: &adw::NavigationView) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header(app));
    let page = adw::PreferencesPage::new();
    let form = Rc::new(RefCell::new(Form::default()));

    let what = step_group(
        "1",
        "¿Qué quieres copiar?",
        "Marca el disco entero o solo las particiones que quieras.",
    );
    page.add(&what);
    let dest = step_group(
        "2",
        "¿Dónde la guardo?",
        "En otro disco (un USB, por ejemplo). Se crea la carpeta partshield-copias y no se \
         borra nada de lo que haya.",
    );
    page.add(&dest);

    let summary = plain_row("", "");
    summary.add_prefix(&gtk::Image::from_icon_name("dialog-information-symbolic"));
    let go = gtk::Button::builder()
        .label("Copiar y comprobar")
        .halign(gtk::Align::Center)
        .margin_top(12)
        .build();
    go.add_css_class("pill");
    go.add_css_class("suggested-action");
    let start = step_group("3", "Empezar", "");
    start.add(&summary);
    let go_group = adw::PreferencesGroup::new();
    go_group.add(&go);
    page.add(&start);
    page.add(&go_group);

    let disks = match model::list_disks() {
        Ok((d, _)) => d,
        Err(e) => {
            toolbar.set_content(Some(&error_status(
                "No se pudieron leer los discos",
                &format!("{e:#}"),
            )));
            return nav_page(&toolbar);
        }
    };
    let loops = std::env::var_os("PARTSHIELD_SANDBOX").is_some();
    let shown: Vec<Disk> = model::basic_disks(&disks, loops)
        .into_iter()
        .cloned()
        .collect();
    let default = model::default_disk(&shown.iter().collect::<Vec<_>>());
    form.borrow_mut().disks = disks;

    // Recalcula destinos, resumen y botón tras cada cambio.
    let refresh: Rc<dyn Fn()> = {
        let (form, dest, summary, go) = (form.clone(), dest.clone(), summary.clone(), go.clone());
        Rc::new(move || refresh_form(&form, &dest, &summary, &go))
    };

    if shown.is_empty() {
        what.add(&plain_row(
            "No hay discos que copiar",
            "Solo se ve el USB de PartShield. Conecta el disco y vuelve a entrar.",
        ));
    }
    let updating = Rc::new(Cell::new(false));
    for disk in shown {
        let pick = disk_rows(&what, disk, default.as_ref(), &updating, &refresh);
        form.borrow_mut().picks.push(pick);
    }
    refresh();

    {
        let (app, nav, form) = (app.clone(), nav.clone(), form.clone());
        go.connect_clicked(move |_| {
            let f = form.borrow();
            let Some(dest) = f.dest().cloned() else {
                return;
            };
            let whole: Vec<PathBuf> = f
                .picks
                .iter()
                .filter(|p| p.whole() && p.disk.volumes.iter().any(|v| v.path != p.disk.path))
                .map(|p| p.disk.path.clone())
                .collect();
            nav.push(&progress_page(&app, &nav, f.items(), whole, dest));
        });
    }

    toolbar.set_content(Some(&page));
    nav_page(&toolbar)
}

fn nav_page(toolbar: &adw::ToolbarView) -> adw::NavigationPage {
    adw::NavigationPage::builder()
        .title("Hacer copia")
        .child(toolbar)
        .build()
}

fn step_group(n: &str, title: &str, text: &str) -> adw::PreferencesGroup {
    let g = group(
        &format!("{n} · {title}"),
        (!text.is_empty()).then_some(text),
    );
    g.add_css_class("step");
    g
}

/// Fila desplegable del disco con una casilla, y una fila con casilla por
/// partición. Marcar el disco marca sus particiones (menos la swap).
fn disk_rows(
    what: &adw::PreferencesGroup,
    disk: Disk,
    default: Option<&PathBuf>,
    updating: &Rc<Cell<bool>>,
    refresh: &Rc<dyn Fn()>,
) -> DiskPick {
    let is_default = default == Some(&disk.path);
    let exp = adw::ExpanderRow::new();
    exp.set_use_markup(false);
    exp.set_title(&model::disk_title(&disk));
    let mut sub = vec![disk.path.display().to_string()];
    if let Some(s) = &disk.serial {
        sub.push(format!("n.º de serie {s}"));
    }
    exp.set_subtitle(&sub.join(" · "));
    exp.add_prefix(&gtk::Image::from_icon_name(
        if disk.transport.as_deref() == Some("usb") || disk.removable {
            "drive-removable-media-symbolic"
        } else {
            "drive-harddisk-symbolic"
        },
    ));
    let check = gtk::CheckButton::new();
    check.set_valign(gtk::Align::Center);
    check.set_tooltip_text(Some("Disco entero"));
    exp.add_prefix(&check);
    exp.set_expanded(is_default);
    what.add(&exp);

    let mut parts = Vec::new();
    for v in disk.volumes.iter().filter(|v| v.depth == 0) {
        let c = gtk::CheckButton::new();
        c.set_valign(gtk::Align::Center);
        c.set_active(is_default && model::checked_with_disk(v));
        let row = plain_row(
            &format!("{} · {}", model::volume_title(v), human_size(v.size)),
            &part_hint(v),
        );
        row.add_prefix(&c);
        row.set_activatable_widget(Some(&c));
        exp.add_row(&row);
        parts.push((v.clone(), c));
    }
    let pick = DiskPick {
        disk,
        check: check.clone(),
        parts,
    };
    sync_disk_check(&pick.check, &pick.parts);

    let part_checks: Vec<(Volume, gtk::CheckButton)> = pick.parts.clone();
    {
        let (updating, refresh, parts) = (updating.clone(), refresh.clone(), part_checks.clone());
        check.connect_toggled(move |c| {
            if updating.get() {
                return;
            }
            updating.set(true);
            let on = c.is_active() || c.is_inconsistent();
            for (v, pc) in &parts {
                pc.set_active(on && model::checked_with_disk(v));
            }
            sync_disk_check(c, &parts);
            updating.set(false);
            refresh();
        });
    }
    for (_, pc) in &part_checks {
        let (updating, refresh, parts, check) = (
            updating.clone(),
            refresh.clone(),
            part_checks.clone(),
            check.clone(),
        );
        pc.connect_toggled(move |_| {
            if updating.get() {
                return;
            }
            updating.set(true);
            sync_disk_check(&check, &parts);
            updating.set(false);
            refresh();
        });
    }
    pick
}

/// Casilla del disco: marcada, vacía o a medias.
fn sync_disk_check(check: &gtk::CheckButton, parts: &[(Volume, gtk::CheckButton)]) {
    let any = parts.iter().any(|(_, c)| c.is_active());
    let all = any
        && parts
            .iter()
            .all(|(v, c)| c.is_active() || !model::checked_with_disk(v));
    check.set_inconsistent(any && !all);
    check.set_active(all);
}

fn part_hint(v: &Volume) -> String {
    let mut s = match v.fstype.as_deref() {
        Some("btrfs") => "Se copian los datos y se comprueba la copia restaurándola".to_string(),
        Some("crypto_LUKS") => "Se copia cifrada y entera, sector a sector".to_string(),
        Some("swap") => "No hace falta copiarla: el sistema la vuelve a crear".to_string(),
        _ => "Se copia entera, sector a sector, y se compara bit a bit".to_string(),
    };
    if let Some(m) = v.mountpoints.iter().find(|m| m.starts_with('/')) {
        s.push_str(&format!(" · montada en {m}"));
    }
    s
}

fn refresh_form(
    form: &Rc<RefCell<Form>>,
    dest: &adw::PreferencesGroup,
    summary: &adw::ActionRow,
    go: &gtk::Button,
) {
    let mut f = form.borrow_mut();
    let sources = f.sources();
    // Sin nada marcado no se ofrece destino: saldrían particiones del
    // mismo disco que luego se querrá copiar.
    let found = if sources.is_empty() {
        Vec::new()
    } else {
        model::destinations(&f.disks, &sources)
    };
    let nothing = sources.is_empty();
    let same = !f.dest_rows.is_empty()
        && found.len() == f.dests.len()
        && !(found.is_empty() && f.dest_rows.len() == 1)
        && found
            .iter()
            .zip(&f.dests)
            .all(|(a, (b, _))| a.device == b.device);
    if !same {
        let previous = f.dest().map(|d| d.device.clone());
        for r in f.dest_rows.drain(..) {
            dest.remove(&r);
        }
        let mut dests = Vec::new();
        // Ancla del grupo, nunca visible: con ella hasta un único destino se
        // dibuja como botón de radio y no se puede desmarcar.
        let anchor = gtk::CheckButton::new();
        for d in found {
            let radio = gtk::CheckButton::new();
            radio.set_valign(gtk::Align::Center);
            radio.set_group(Some(&anchor));
            let free = d
                .mountpoint
                .as_deref()
                .and_then(model::free_bytes)
                .map(|b| format!(" · {} libres", human_size(b)))
                .unwrap_or_default();
            let row = plain_row(
                &format!("{} · {}", d.disk, d.title()),
                &format!("{} · {}{free}", d.fstype, human_size(d.size)),
            );
            row.add_prefix(&radio);
            row.set_activatable_widget(Some(&radio));
            dest.add(&row);
            f.dest_rows.push(row);
            dests.push((d, radio));
        }
        let keep = dests
            .iter()
            .position(|(d, _)| Some(&d.device) == previous.as_ref())
            .unwrap_or(0);
        if let Some((_, r)) = dests.get(keep) {
            r.set_active(true);
        }
        if nothing {
            let row = plain_row("Primero marca qué quieres copiar", "");
            row.add_css_class("dim-label");
            dest.add(&row);
            f.dest_rows.push(row);
        } else if dests.is_empty() {
            let row = plain_row(
                "No hay dónde guardarla",
                "Conecta un disco USB con espacio libre (ext4, Btrfs, exFAT, NTFS…) y vuelve \
                 a entrar en «Hacer copia». Para prepararlo, usa GParted en Herramientas.",
            );
            row.add_prefix(&gtk::Image::from_icon_name("dialog-warning-symbolic"));
            dest.add(&row);
            f.dest_rows.push(row);
        }
        for (_, r) in &dests {
            let (form, dest, summary, go) =
                (form.clone(), dest.clone(), summary.clone(), go.clone());
            r.connect_toggled(move |r| {
                if r.is_active() {
                    refresh_form(&form, &dest, &summary, &go);
                }
            });
        }
        f.dests = dests;
        f.radio_anchor = Some(anchor);
    }

    let items = f.items();
    let sizes: u64 = f
        .picks
        .iter()
        .flat_map(|p| p.chosen())
        .map(|v| PlanItem::new(v).max_bytes(v.size))
        .sum();
    let free = f
        .dest()
        .and_then(|d| d.mountpoint.as_deref())
        .and_then(model::free_bytes);
    let (title, text, ok) = if items.is_empty() {
        ("Marca algo que copiar".to_string(), String::new(), false)
    } else if f.dest().is_none() {
        ("Falta el destino".to_string(), String::new(), false)
    } else {
        let n = items.len();
        let title = format!(
            "{n} {} · hasta {} antes de comprimir",
            if n == 1 { "parte" } else { "partes" },
            human_size(sizes)
        );
        let text = match free {
            Some(b) if b < sizes => format!(
                "Puede que no quepa: el destino tiene {} libres. Comprimida suele ocupar \
                 bastante menos, pero no está garantizado.",
                human_size(b)
            ),
            Some(b) => format!("Cabe: el destino tiene {} libres.", human_size(b)),
            None => "El espacio libre del destino se comprueba al empezar.".into(),
        };
        (title, text, true)
    };
    summary.set_title(&title);
    summary.set_subtitle(&text);
    go.set_sensitive(ok);
}

// ---------------------------------------------------------------- progreso

fn progress_page(
    app: &adw::Application,
    nav: &adw::NavigationView,
    items: Vec<PlanItem>,
    whole: Vec<PathBuf>,
    dest: Destination,
) -> adw::NavigationPage {
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header(app));
    let page = adw::NavigationPage::builder()
        .title("Copiando")
        .child(&toolbar)
        .can_pop(false)
        .build();

    let bar = gtk::ProgressBar::builder().show_text(true).build();
    let part = gtk::Label::new(None);
    part.add_css_class("step-title");
    part.set_wrap(true);
    let phase = gtk::Label::new(Some("Preparando…"));
    phase.add_css_class("dim-label");
    let elapsed = gtk::Label::new(Some("0:00"));
    elapsed.add_css_class("numeric");
    elapsed.add_css_class("dim-label");
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
        .min_content_height(220)
        .build();
    scroll.add_css_class("card");
    let details = gtk::Expander::builder()
        .label("Ver detalles")
        .child(&scroll)
        .margin_top(12)
        .build();
    let col = gtk::Box::new(gtk::Orientation::Vertical, 8);
    col.append(&part);
    col.append(&bar);
    col.append(&phase);
    col.append(&elapsed);
    col.append(&details);
    let status = adw::StatusPage::builder()
        .icon_name("document-save-symbolic")
        .title("Copiando y comprobando")
        .description("No apagues el equipo ni desconectes el disco de destino.")
        .child(&adw::Clamp::builder().maximum_size(640).child(&col).build())
        .vexpand(true)
        .build();
    toolbar.set_content(Some(&status));

    let n = items.len();
    let (tx, rx) = mpsc::channel::<PlanEvent>();
    let results: Rc<RefCell<Vec<Option<Result<(Report, PathBuf), String>>>>> =
        Rc::new(RefCell::new((0..n).map(|_| None).collect()));
    let tables: Rc<RefCell<Vec<Result<PathBuf, String>>>> = Rc::default();
    let current = Rc::new(Cell::new(0usize));
    let verifying = Rc::new(Cell::new(false));
    let start = Instant::now();
    let titles: Vec<String> = items.iter().map(|i| i.title.clone()).collect();
    {
        let (results, tables, current, verifying) = (
            results.clone(),
            tables.clone(),
            current.clone(),
            verifying.clone(),
        );
        let (bar, part, phase, elapsed, log, scroll) = (
            bar.clone(),
            part.clone(),
            phase.clone(),
            elapsed.clone(),
            log.clone(),
            scroll.clone(),
        );
        let (tb, nav, page2) = (toolbar.clone(), nav.clone(), page.clone());
        glib::timeout_add_local(Duration::from_millis(250), move || {
            let buf = log.buffer();
            let mut finished = false;
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    PlanEvent::Part(i) => {
                        current.set(i);
                        verifying.set(false);
                    }
                    PlanEvent::Command(c) => {
                        if is_verify_command(&c) {
                            verifying.set(true);
                        }
                        buf.insert(&mut buf.end_iter(), &format!("$ {c}\n"));
                        let adj = scroll.vadjustment();
                        adj.set_value(adj.upper());
                    }
                    PlanEvent::Done(i, r) => {
                        results.borrow_mut()[i] = Some(r);
                        finished = i + 1 == n;
                    }
                    PlanEvent::Table(r) => tables.borrow_mut().push(r),
                }
            }
            let i = current.get();
            let done = results.borrow().iter().filter(|r| r.is_some()).count();
            // Por partes: la copia es la primera mitad de cada una y la
            // comprobación la segunda. No es un porcentaje de bytes.
            let frac = if finished {
                1.0
            } else {
                (done as f64 + if verifying.get() { 0.5 } else { 0.0 }) / n.max(1) as f64
            };
            bar.set_fraction(frac);
            bar.set_text(Some(&format!("{}%", (frac * 100.0).round())));
            part.set_text(&format!(
                "Parte {} de {n} · {}",
                (i + 1).min(n),
                titles.get(i).map(String::as_str).unwrap_or("")
            ));
            phase.set_text(if verifying.get() {
                "Comprobando la copia: se restaura aparte y se compara con el original…"
            } else {
                "Copiando…"
            });
            let secs = start.elapsed().as_secs();
            elapsed.set_text(&format!(
                "{}:{:02}:{:02}",
                secs / 3600,
                secs / 60 % 60,
                secs % 60
            ));
            if finished {
                let r: Vec<_> = results.borrow_mut().drain(..).flatten().collect();
                tb.set_content(Some(&summary_view(&nav, &titles, r, &tables.borrow())));
                page2.set_can_pop(true);
                page2.set_title("Resultado");
                glib::ControlFlow::Break
            } else {
                glib::ControlFlow::Continue
            }
        });
    }
    gio::spawn_blocking(move || model::run_plan(&items, &whole, &dest, tx));
    page
}

/// La copia ha terminado y empieza la comprobación (restaurar aparte).
fn is_verify_command(c: &str) -> bool {
    c.starts_with("btrfs receive") || c.starts_with("losetup") || c.starts_with("mkfs")
}

// --------------------------------------------------------------- resultado

fn summary_view(
    nav: &adw::NavigationView,
    titles: &[String],
    results: Vec<Result<(Report, PathBuf), String>>,
    tables: &[Result<PathBuf, String>],
) -> gtk::Widget {
    let results: Vec<Result<(Rc<Report>, PathBuf), String>> = results
        .into_iter()
        .map(|r| r.map(|(rep, p)| (Rc::new(rep), p)))
        .collect();
    let page = adw::PreferencesPage::new();
    // 0 válida, 1 sin verificar del todo, 2 no vale.
    let level = |r: &Result<(Rc<Report>, PathBuf), String>| match r {
        Ok((rep, _)) if rep.error.is_none() => match rep.verdict() {
            Verdict::Valid => 0,
            Verdict::Reduced => 1,
            Verdict::Invalid => 2,
        },
        _ => 2,
    };
    let worst = results.iter().map(level).max().unwrap_or(2);
    let (icon, title, desc, css) = match worst {
        0 => (
            "emblem-ok-symbolic",
            "Copia comprobada",
            "Se ha restaurado aparte y coincide con el original: se puede restaurar.",
            "success",
        ),
        1 => (
            "dialog-warning-symbolic",
            "Copia hecha, pero sin comprobar del todo",
            "No falló nada, pero algún paso de la comprobación no se pudo hacer. Mira \
             abajo cuál antes de fiarte.",
            "warning",
        ),
        _ => (
            "dialog-error-symbolic",
            "Esta copia NO vale",
            "Alguna parte falló o no pasó la comprobación. No confíes en ella.",
            "error",
        ),
    };
    let head = adw::StatusPage::builder()
        .icon_name(icon)
        .title(title)
        .description(desc)
        .build();
    head.add_css_class(css);
    head.add_css_class("compact");
    let hg = adw::PreferencesGroup::new();
    hg.add(&head);
    page.add(&hg);

    let parts = group(
        "Partes",
        Some("Pulsa una para ver la comprobación paso a paso."),
    );
    for (t, r) in titles.iter().zip(&results) {
        let (word, class, icon) = match level(r) {
            0 => ("Comprobada", "verdict-ok", "emblem-ok-symbolic"),
            1 => (
                "Sin comprobar del todo",
                "verdict-warn",
                "dialog-warning-symbolic",
            ),
            _ => ("No vale", "verdict-bad", "dialog-error-symbolic"),
        };
        let detail = match r {
            Ok(_) => word.to_string(),
            Err(e) => format!("{word}: {e}"),
        };
        let row = plain_row(t, &detail);
        let img = gtk::Image::from_icon_name(icon);
        img.add_css_class(class);
        row.add_prefix(&img);
        if let Ok((report, path)) = r {
            row.set_activatable(true);
            row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
            let (nav, report, path) = (nav.clone(), report.clone(), path.clone());
            row.connect_activated(move |_| {
                let tb = adw::ToolbarView::new();
                tb.add_top_bar(&adw::HeaderBar::new());
                tb.set_content(Some(&result_view(&nav, &report, &path)));
                nav.push(
                    &adw::NavigationPage::builder()
                        .title("Detalle")
                        .child(&tb)
                        .build(),
                );
            });
        }
        parts.add(&row);
    }
    page.add(&parts);

    if !tables.is_empty() {
        let tg = group("Tabla de particiones", None);
        for t in tables {
            tg.add(&match t {
                Ok(p) => plain_row("Guardada", &p.display().to_string()),
                Err(e) => plain_row("No se pudo guardar", e),
            });
        }
        page.add(&tg);
    }

    let back = gtk::Button::builder()
        .label("Volver al inicio")
        .halign(gtk::Align::Center)
        .build();
    back.add_css_class("pill");
    {
        let nav = nav.clone();
        back.connect_clicked(move |_| {
            nav.pop_to_tag("inicio");
        });
    }
    let g = adw::PreferencesGroup::new();
    g.add(&back);
    page.add(&g);
    page.upcast()
}
