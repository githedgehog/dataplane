// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! User terminal frontend

use crate::cmdtree::Node;
use rustyline::config::{ColorMode, CompletionType, Config};
use rustyline::{Cmd, Event, KeyCode, KeyEvent, Modifiers};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::rc::Rc;

// our completer
use crate::completions::CmdCompleter;

fn rustyline_editor_config() -> Config {
    Config::builder()
        .auto_add_history(false)
        .history_ignore_dups(true)
        .max_history_size(400)
        .color_mode(ColorMode::Enabled)
        .completion_type(CompletionType::List)
        .build()
}

pub struct Terminal {
    prompt: String,
    prompt_name: String,
    cmdtree: Rc<Node>,
    editor: rustyline::Editor<CmdCompleter>,
    run: bool,
    connected: bool,
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
            editor: rustyline::Editor::<CmdCompleter>::with_config(rustyline_editor_config()),
            run: true,
            connected: false,
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
            Event::KeySeq(SmallVec::from(vec![KeyEvent(
                KeyCode::Tab,
                Modifiers::NONE,
            )])),
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
}
