// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds command completions

use crate::cmdtree::Node;
use rustyline::Helper;
use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Default)]
pub struct CmdCompleter {
    cmdtree: Rc<Node>,
}
#[allow(unused)]
impl CmdCompleter {
    pub fn new(cmdtree: Rc<Node>) -> Self {
        Self { cmdtree }
    }
    #[allow(unused)]
    pub fn get_commands(&self) -> &Node {
        &self.cmdtree
    }
}

impl Hinter for CmdCompleter {
    type Hint = String;
}
impl Highlighter for CmdCompleter {}
impl Validator for CmdCompleter {}
impl Helper for CmdCompleter {}
impl Completer for CmdCompleter {
    type Candidate = String; // may want this to be s/t different
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let mut matched: VecDeque<&str> = VecDeque::new();
        let mut left: VecDeque<&str> = line.split_whitespace().collect();
        let node = self.cmdtree.lookup(&mut left, &mut matched);
        let mut candidates: Vec<String> =
            node.children.values().map(|cmd| cmd.name.clone()).collect();

        // if line has args, don't offer child nodes: only expect args/choices
        if line.contains("=") {
            candidates.truncate(0);
        }

        // remove completed arg pairs from leftovers
        left = left
            .iter()
            .filter(|word| match word.split_once("=") {
                Some((_arg, val)) => val.is_empty(),
                None => true,
            })
            .cloned()
            .collect();

        // always offer args if there, except those already in the line
        for arg in &node.args {
            if !line.contains(&arg.name) {
                candidates.push(arg.name.clone() + "=");
            }
        }

        // FIXME
        if let Some(word) = left.front() {
            if word.contains("=") {
                #[allow(clippy::collapsible_if)]
                if let Some((arg_side, value_side)) = word.split_once("=") {
                    if let Some(arg) = node.find_arg(arg_side) {
                        // if left side of = is arg and it has choices, offer them
                        if !arg.choices.is_empty() {
                            candidates.truncate(0); //  not needed. the next code truncates
                            candidates = arg.choices.iter().filter(|_| true).cloned().collect();
                        }
                        if !value_side.is_empty() {
                            candidates = candidates
                                .iter()
                                .filter(|choice| choice.starts_with(value_side))
                                .cloned()
                                .collect();
                        }
                    }
                }
            } else if !word.is_empty() {
                candidates = candidates
                    .iter()
                    .filter(|cand| cand.to_lowercase().starts_with(word))
                    .cloned()
                    .collect();
            }
        }

        let mut newpos = 0;
        if !matched.is_empty() {
            let last = matched.pop_back().unwrap();
            newpos = line.find(last).unwrap() + last.len() + 1;
            if newpos > pos {
                newpos = pos;
            }
        }
        Ok((newpos, candidates))
    }
}
