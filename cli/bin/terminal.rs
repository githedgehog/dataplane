// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! User terminal frontend

use crate::cmdtree::Node;
use crate::prefetch::prefetch;
use colored::Colorize;
use dataplane_cli::cliproto::{CLI_RX_BUFF_SIZE, PrefetchSelector};
use nix::sys::socket::{setsockopt, sockopt::RcvBuf};
use reedline::{
    Emacs, IdeMenu, KeyCode, KeyModifiers, MenuBuilder, Prompt, PromptEditMode,
    PromptHistorySearch, Reedline, ReedlineEvent, ReedlineMenu, Signal, default_emacs_keybindings,
};

use concurrency::sync::{Arc, Mutex};
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

// our completer
use crate::completions::CmdCompleter;

// filters
use crate::filters::{Filter, PIPE, parse_filters};

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

/// State shared between the terminal and the completer: the socket to send
/// user requests and prefecth requests and the values prefetched for a line
/// for autocompletion
#[derive(Default)]
pub struct Session {
    sock: Option<UnixDatagram>,
    prefetched: HashMap<PrefetchSelector, Vec<String>>,
}

impl Session {
    /// Prefetch completion values for `selector`.
    /// Prefetching happens at most once per line, since we cache the reply
    /// data.
    ///
    /// When invoked for the first time, no value exists for selector and
    /// an empty vector is stored so that we can differentiate between no values
    /// available or not attempted to pre-fetch.
    pub fn prefetch(&mut self, selector: PrefetchSelector) -> &[String] {
        let sock = &self.sock;
        self.prefetched.entry(selector).or_insert_with(|| {
            sock.as_ref()
                .map(|sock| prefetch(sock, selector))
                .unwrap_or_default()
        })
    }

    /// Forget all prefetched values
    pub fn invalidate(&mut self) {
        self.prefetched.clear();
    }
}

pub type SharedSession = Arc<Mutex<Session>>;

/// Run `f` over the shared socket, if one has been opened, holding the lock
/// for the whole call so that a request and its response are not interleaved
/// with another user of the socket. Returns `None` if there is no socket.
pub fn with_sock<R>(session: &SharedSession, f: impl FnOnce(&UnixDatagram) -> R) -> Option<R> {
    session.lock().sock.as_ref().map(f)
}

pub struct Terminal {
    prompt: String,
    prompt_name: String,
    cmdtree: Arc<Node>,
    editor: Reedline,
    run: bool,
    connected: bool,
    pub session: SharedSession,
}

#[derive(Debug, Default)]
pub struct TermInput {
    line: String,
    tokens: VecDeque<String>,
    args: HashMap<String, String>,
    filters: Vec<Filter>,
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
    pub fn get_filters(&self) -> &Vec<Filter> {
        &self.filters
    }
    fn empty() -> Self {
        Self::default()
    }
}

#[allow(unused)]
impl Terminal {
    pub fn new(prompt: &str, cmdtree: &Arc<Node>) -> Self {
        let session: SharedSession = Arc::new(Mutex::new(Session::default()));
        let completer = Box::new(CmdCompleter::new(cmdtree.clone(), session.clone()));
        let completion_menu = Box::new(IdeMenu::default().with_name("completion_menu"));

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
            .with_quick_completions(true)
            .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
            .with_edit_mode(edit_mode)
            .with_ansi_colors(false);

        let mut term = Self {
            prompt: prompt.to_owned(),
            prompt_name: prompt.to_owned(),
            cmdtree: cmdtree.clone(),
            editor,
            run: true,
            connected: false,
            session,
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

    pub fn proc_line(line: &str) -> Option<TermInput> {
        let mut split = line.split_whitespace();
        let mut tokens: VecDeque<String> = VecDeque::new();
        let mut args = HashMap::new();
        let mut filters = Vec::new();
        while let Some(word) = split.next() {
            if word.contains('=') {
                if let Some((arg, arg_value)) = word.split_once('=') {
                    args.insert(arg.to_owned(), arg_value.to_owned());
                }
            } else if word == PIPE {
                if let Err(e) = parse_filters(split, &mut filters) {
                    print_err!("{e}");
                    return None;
                }
                break;
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
                filters,
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
            let signal = self.editor.read_line(&cli_prompt);
            // The line edit is over: values prefetched for it must not be
            // offered as completions for the next one.
            self.session.lock().invalidate();
            match signal {
                Ok(Signal::Success(line)) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some(c) = Self::proc_line(line) {
                        return c;
                    }
                }
                Ok(Signal::CtrlD | Signal::CtrlC) => {
                    self.run = false;
                    return TermInput::empty();
                }
                _ => {}
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
        let shut = {
            let mut session = self.session.lock();
            session.invalidate();
            session
                .sock
                .as_ref()
                .map(|sock| sock.shutdown(Shutdown::Both).is_ok())
        };
        if shut == Some(true) {
            self.connected(false);
        }
    }

    pub fn connect<P: AsRef<Path>>(&mut self, local_addr: &P, remote_addr: &P) {
        if self.is_connected() {
            self.disconnect();
        }
        let connected = {
            // replace the socket in place: the completer shares this handle
            let mut shared = self.session.lock();
            if let Ok(new_sock) = Self::open_unix_sock(local_addr) {
                shared.sock = Some(new_sock);
            }
            // the peer may not be the one the cached values came from
            shared.invalidate();
            if let Some(sock) = shared.sock.as_ref() {
                sock.connect(remote_addr)
                    .inspect_err(|error| {
                        print_err!(
                            "Failed to connect to '{:?}': {}",
                            remote_addr.as_ref(),
                            error
                        );
                    })
                    .is_ok()
            } else {
                print_err!(
                    "Failed to connect to '{:?}': no local socket",
                    remote_addr.as_ref()
                );
                false
            }
        };
        if connected {
            self.connected(true);
        }
    }
}
