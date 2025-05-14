// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! User terminal frontend

use crate::cmdtree::Node;
use colored::Colorize;
use rustyline::config::{ColorMode, CompletionType, Config};
use rustyline::history::MemHistory;
use rustyline::{Cmd, Event, KeyCode, KeyEvent, Modifiers};
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::io::stdout;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::rc::Rc;

// our completer
use crate::completions::CmdCompleter;

#[macro_export]
// macro to print errors in cli binary
macro_rules! print_err {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*).red();
        println!(" {}",msg);
    }};
}

fn rustyline_editor_config() -> Config {
    Config::builder()
        .auto_add_history(false)
        .history_ignore_dups(true)
        .expect("Editor config:'history ignore dups' failed")
        .max_history_size(400)
        .expect("Editor config:'max-history size' failed")
        .color_mode(ColorMode::Enabled)
        .completion_type(CompletionType::List)
        .build()
}

pub struct Terminal {
    prompt: String,
    prompt_name: String,
    cmdtree: Rc<Node>,
    editor: rustyline::Editor<CmdCompleter, MemHistory>,
    run: bool,
    connected: bool,
    pub sock: UnixDatagram,
}

#[derive(Debug)]
pub struct TermInput {
    line: String,
    tokens: VecDeque<String>,
}
#[allow(unused)]
impl TermInput {
    pub fn get_line(&self) -> &str {
        &self.line
    }
    pub fn get_tokens(&mut self) -> &mut VecDeque<String> {
        &mut self.tokens
    }
}

#[allow(unused)]
impl Terminal {
    pub fn new(prompt: &str, cmdtree: Rc<Node>) -> Self {
        let mut term = Self {
            prompt: prompt.to_owned(),
            prompt_name: prompt.to_owned(),
            cmdtree: cmdtree.clone(),
            editor: rustyline::Editor::<CmdCompleter, MemHistory>::with_config(
                rustyline_editor_config(),
            )
            .expect("Editor config failed"),
            run: true,
            connected: false,
            sock: UnixDatagram::unbound().expect("Failed to create unix socket"),
        }
        .set_helper(CmdCompleter::new(cmdtree.clone()));
        term.set_prompt();
        term
    }
    pub fn stop(&mut self) {
        self.run = false;
    }
    pub fn runs(&self) -> bool {
        self.run
    }
    pub fn get_cmd_tree(&self) -> &Node {
        self.cmdtree.as_ref()
    }
    pub fn set_helper(mut self, helper: CmdCompleter) -> Self {
        self.editor.set_helper(Some(helper));
        self.editor.bind_sequence(
            Event::KeySeq(vec![KeyEvent(KeyCode::Tab, Modifiers::NONE)]),
            Cmd::Complete,
        );
        self
    }
    pub fn add_history_entry<S: AsRef<str> + Into<String>>(&mut self, line: S) {
        self.editor.add_history_entry(line);
    }

    #[allow(unused)]
    pub fn get_helper(&self) -> Option<&CmdCompleter> {
        self.editor.helper()
    }
    pub fn clear(&self) {
        print!("\x1b[H\x1b[2J");
        let _ = stdout().flush();
    }
    fn proc_line(&mut self, line: &str) -> Option<TermInput> {
        let mut split = line.split_whitespace();
        if let Some(word) = split.next() {
            let mut args: VecDeque<String> = VecDeque::new();
            args.push_back(word.to_owned());
            split.by_ref().for_each(|x| args.push_back(x.to_owned()));

            Some(TermInput {
                line: line.to_owned(),
                tokens: args,
            })
        } else {
            None
        }
    }
    fn set_prompt(&mut self) {
        if self.connected {
            self.prompt = self.prompt_name.to_owned() + "(✔)# ";
        } else {
            self.prompt = self.prompt_name.to_owned() + "(✖)# ";
        }
    }
    pub fn prompt(&mut self) -> TermInput {
        loop {
            let input = self.editor.readline(&self.prompt);
            if let Ok(line) = input {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(c) = self.proc_line(line) {
                    return c;
                }
            }
        }
    }
    pub fn connected(&mut self, value: bool) {
        self.connected = value;
        self.set_prompt();
    }
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    fn open_unix_sock<P: AsRef<Path>>(bind_addr: &P) -> Result<UnixDatagram, &'static str> {
        let _ = std::fs::remove_file(bind_addr);
        let sock = UnixDatagram::bind(bind_addr).map_err(|_| "Failed to bind socket")?;
        let mut perms = fs::metadata(bind_addr)
            .map_err(|_| "Failed to retrieve path metadata")?
            .permissions();
        perms.set_mode(0o777);
        fs::set_permissions(bind_addr, perms).map_err(|_| "Failure setting permissions")?;
        sock.set_nonblocking(false)
            .map_err(|_| "Failed to set non-blocking")?;
        Ok(sock)
    }

    pub fn disconnect(&mut self) {
        if let Ok(()) = self.sock.shutdown(Shutdown::Both) {
            self.connected(false);
        }
    }

    pub fn connect<P: AsRef<Path>>(&mut self, local_addr: &P, remote_addr: &P) {
        if self.is_connected() {
            self.disconnect();
        }
        if let Ok(new_sock) = Self::open_unix_sock(local_addr) {
            self.sock = new_sock;
        }
        if let Err(error) = self.sock.connect(remote_addr) {
            print_err!(
                "Failed to connect to '{:?}': {}",
                remote_addr.as_ref(),
                error
            );
        } else {
            self.connected(true);
        }
    }
}
