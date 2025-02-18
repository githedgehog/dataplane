// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds command completions

use crate::cmdtree::Node;
use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::Helper;
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

        // offer child nodes if there
        if !node.children.is_empty() {
            // check if leftover is prefix of any children node
            if let Some(word) = left.front() {
                candidates = candidates
                    .iter()
                    .filter(|child| child.to_lowercase().starts_with(word))
                    .cloned()
                    .collect();
            };
        } else {
            // Otherwise, offer args if present and not already input
            for arg in &node.args {
                if !line.contains(&arg.name) {
                    candidates.push(arg.name.to_owned() + "=");
                }
            }

            // FIXME
            if let Some(word) = left.front() {
                if word.contains("=") {
                    if let Some((arg_side, _value_side)) = word.split_once("=") {
                        if let Some(arg) = node.find_arg(arg_side) {
                            if !arg.choices.is_empty() {
                                candidates.truncate(0);
                                for choice in arg.choices.iter() {
                                    candidates.push(choice.to_owned());
                                }
                            }
                        }
                    }
                }
            }
        }

        //        if let Some(longest) = longest_common_prefix(candidates.as_ref()) {
        //            println!("\n{longest}");
        //        }
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
