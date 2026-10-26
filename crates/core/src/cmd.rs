//! Runs external tools and keeps a record of every command executed.
//!
//! The GUI shows these records verbatim, so a user can always see exactly
//! what ran and repeat it by hand.

use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Cmd {
    program: OsString,
    args: Vec<OsString>,
}

impl Cmd {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.args);
        c
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", quote(&self.program))?;
        for a in &self.args {
            write!(f, " {}", quote(a))?;
        }
        Ok(())
    }
}

fn quote(s: &OsString) -> String {
    let s = s.to_string_lossy();
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        s.into_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandRecord {
    pub command: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
}

#[derive(Debug, Default)]
pub struct Session {
    pub records: Vec<CommandRecord>,
    /// Print each command to stderr before running it.
    pub echo: bool,
}

impl Session {
    pub fn new(echo: bool) -> Self {
        Self {
            records: Vec::new(),
            echo,
        }
    }

    fn announce(&self, cmd: &Cmd) {
        if self.echo {
            eprintln!("$ {cmd}");
        }
    }

    fn record(&mut self, cmd: &Cmd, code: Option<i32>, start: Instant) {
        self.records.push(CommandRecord {
            command: cmd.to_string(),
            exit_code: code,
            duration_ms: start.elapsed().as_millis(),
        });
    }

    /// Runs a command to completion and returns its stdout. Fails on a
    /// non-zero exit, including stderr in the error.
    pub fn run(&mut self, cmd: Cmd) -> Result<String> {
        let out = self.run_unchecked(&cmd)?;
        if !out.success {
            bail!(
                "`{cmd}` falló (código {:?}): {}",
                out.code,
                out.stderr.trim()
            );
        }
        Ok(out.stdout)
    }

    pub fn run_unchecked(&mut self, cmd: &Cmd) -> Result<Output> {
        self.announce(cmd);
        let start = Instant::now();
        let out = cmd
            .command()
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("no se pudo ejecutar `{cmd}`"))?;
        self.record(cmd, out.status.code(), start);
        Ok(Output {
            success: out.status.success(),
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Runs `cmd` with its stdout handed to `consume`.
    pub fn pipe_out<T>(
        &mut self,
        cmd: Cmd,
        consume: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<T> {
        self.announce(&cmd);
        let start = Instant::now();
        let mut child = spawn(&cmd, Stdio::null(), Stdio::piped())?;
        let mut stdout = child.stdout.take().expect("piped stdout");
        let res = consume(&mut stdout);
        drop(stdout);
        let res = self.finish(&cmd, child, start, res)?;
        Ok(res)
    }

    /// Runs `cmd` with `produce` writing its stdin.
    pub fn pipe_in(
        &mut self,
        cmd: Cmd,
        produce: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        self.announce(&cmd);
        let start = Instant::now();
        let mut child = spawn(&cmd, Stdio::piped(), Stdio::null())?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let res = produce(&mut stdin);
        drop(stdin);
        self.finish(&cmd, child, start, res)
    }

    fn finish<T>(&mut self, cmd: &Cmd, child: Child, start: Instant, res: Result<T>) -> Result<T> {
        let out = child
            .wait_with_output()
            .with_context(|| format!("esperando a `{cmd}`"))?;
        self.record(cmd, out.status.code(), start);
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "`{cmd}` falló (código {:?}): {}",
                out.status.code(),
                stderr.trim()
            );
        }
        res.with_context(|| format!("procesando la salida de `{cmd}`"))
    }
}

fn spawn(cmd: &Cmd, stdin: Stdio, stdout: Stdio) -> Result<Child> {
    cmd.command()
        .stdin(stdin)
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("no se pudo ejecutar `{cmd}`"))
}

#[derive(Debug)]
pub struct Output {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_quotes_only_when_needed() {
        let c = Cmd::new("btrfs")
            .arg("send")
            .arg("/mnt/mis datos")
            .arg("it's");
        assert_eq!(c.to_string(), r"btrfs send '/mnt/mis datos' 'it'\''s'");
    }

    #[test]
    fn records_commands_and_failures() {
        let mut s = Session::new(false);
        assert_eq!(s.run(Cmd::new("echo").arg("hola")).unwrap(), "hola\n");
        assert!(s.run(Cmd::new("false")).is_err());
        assert_eq!(s.records.len(), 2);
        assert_eq!(s.records[0].exit_code, Some(0));
        assert_eq!(s.records[1].exit_code, Some(1));
    }

    #[test]
    fn pipes_both_ways() {
        let mut s = Session::new(false);
        let got = s
            .pipe_out(Cmd::new("printf").arg("abc"), |r| {
                let mut v = String::new();
                r.read_to_string(&mut v)?;
                Ok(v)
            })
            .unwrap();
        assert_eq!(got, "abc");
        s.pipe_in(Cmd::new("cat"), |w| Ok(w.write_all(b"x")?))
            .unwrap();
        assert!(s.pipe_in(Cmd::new("false"), |_| Ok(())).is_err());
    }
}
