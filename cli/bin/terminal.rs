// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! User terminal frontend

use crate::cmdtree::Node;
use colored::Colorize;
use dataplane_cli::cliproto::CLI_RX_BUFF_SIZE;
use nix::sys::socket::{setsockopt, sockopt::RcvBuf};
use reedline::{
    ColumnarMenu, Emacs, KeyCode, KeyModifiers, MenuBuilder, Prompt, PromptEditMode,
    PromptHistorySearch, Reedline, ReedlineEvent, ReedlineMenu, Signal, default_emacs_keybindings,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::io::stdout;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::Arc;

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

struct CliPrompt {
    text: String,
}

impl Prompt for CliPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.text)
    }
    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_history_search_indicator(
        &self,
        _history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
}

pub struct Terminal {
    prompt: String,
    prompt_name: String,
    cmdtree: Arc<Node>,
    editor: Reedline,
    run: bool,
    connected: bool,
    pub sock: UnixDatagram,
}

#[derive(Debug)]
pub struct TermInput {
    line: String,
    tokens: VecDeque<String>,
    args: HashMap<String, String>,
}
#[allow(unused)]
impl TermInput {
    pub fn get_line(&self) -> &str {
        &self.line
    }
    pub fn get_tokens(&mut self) -> &mut VecDeque<String> {
        &mut self.tokens
    }
    pub fn get_args(&self) -> &HashMap<String, String> {
        &self.args
    }
}

#[allow(unused)]
impl Terminal {
    pub fn new(prompt: &str, cmdtree: &Arc<Node>) -> Self {
        let completer = Box::new(CmdCompleter::new(cmdtree.clone()));
        let completion_menu = Box::new(ColumnarMenu::default().with_name("completion_menu"));

        let mut keybindings = default_emacs_keybindings();
        keybindings.add_binding(
            KeyModifiers::NONE,
            KeyCode::Tab,
            ReedlineEvent::UntilFound(vec![
                ReedlineEvent::Menu("completion_menu".to_string()),
                ReedlineEvent::MenuNext,
            ]),
        );
        let edit_mode = Box::new(Emacs::new(keybindings));

        let editor = Reedline::create()
            .with_completer(completer)
            .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
            .with_edit_mode(edit_mode);

        let mut term = Self {
            prompt: prompt.to_owned(),
            prompt_name: prompt.to_owned(),
            cmdtree: cmdtree.clone(),
            editor,
            run: true,
            connected: false,
            sock: UnixDatagram::unbound().expect("Failed to create unix socket"),
        };
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
    #[allow(clippy::unused_self)]
    pub fn clear(&self) {
        print!("\x1b[H\x1b[2J");
        let _ = stdout().flush();
    }
    #[allow(clippy::unused_self)]
    pub fn proc_line(&self, line: &str) -> Option<TermInput> {
        let mut split = line.split_whitespace();
        let mut tokens: VecDeque<String> = VecDeque::new();
        let mut args = HashMap::new();
        for word in split {
            if word.contains('=') {
                if let Some((arg, arg_value)) = word.split_once('=') {
                    args.insert(arg.to_owned(), arg_value.to_owned());
                }
            } else {
                tokens.push_back(word.to_owned());
            }
        }
        if tokens.is_empty() {
            None
        } else {
            Some(TermInput {
                line: line.to_owned(),
                tokens,
                args,
            })
        }
    }
    fn set_prompt(&mut self) {
        if self.connected {
            self.prompt = self.prompt_name.clone() + "(✔)# ";
        } else {
            self.prompt = self.prompt_name.clone() + "(✖)# ";
        }
    }
    pub fn prompt(&mut self) -> TermInput {
        loop {
            let cli_prompt = CliPrompt {
                text: self.prompt.clone(),
            };
            if let Ok(Signal::Success(line)) = self.editor.read_line(&cli_prompt) {
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
    pub fn read_prompt(&self) -> &String {
        &self.prompt
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
            .map_err(|_| "Failed to set sock non-blocking")?;

        setsockopt(&sock, RcvBuf, &CLI_RX_BUFF_SIZE)
            .map_err(|_| "Failure setting recv buffer size")?;
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
