// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds command completions

use crate::cmdtree::Node;
use rustyline::Helper;
use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
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
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let input = &line[..pos];
        let tokens: Vec<String> = input.split_whitespace().map(ToString::to_string).collect();
        let mut candidates = Vec::new();
        let empty = String::new();

        let (path_tokens, last) = if input.ends_with(' ') {
            (tokens.as_slice(), &empty)
        } else {
            let split = tokens.split_at(tokens.len().saturating_sub(1));
            (split.0, split.1.last().unwrap_or(&empty))
        };

        // starting at root, walk down the tree with the tokens
        let mut node = self.cmdtree.as_ref();
        for t in path_tokens {
            // stop if we step on an option
            if t.contains('=') {
                break;
            }
            if let Some(child) = node.children.get(t) {
                node = child;
            } else {
                // node does not have t as children
                return Ok((pos - last.len(), candidates /* empty */));
            }
        }

        // If last token ends with '=', do not attempt to complete the value,
        // except if the node has args and the arg is recognizable and has choices.
        // In that case, expose the choices. If input is arg=XYZ, then expose only
        // the choices that start with xyz.
        if last.contains('=') {
            let (maybearg, value) = last.split_once('=').unwrap_or_else(|| unreachable!());
            if let Some(arg) = node.find_arg(maybearg) {
                candidates.clear(); // sanity
                if !arg.choices.is_empty() {
                    let mut choices: Vec<_> = arg.choices.clone();
                    candidates.append(&mut choices);
                }
                if let Some(prefetch) = &arg.prefetcher {
                    let mut values = prefetch();
                    candidates.append(&mut values);
                }
                // input is arg=fragment
                if !value.is_empty() {
                    candidates.retain(|c| c.starts_with(value));
                    return Ok((pos - value.len(), candidates));
                }
            }
            return Ok((pos - last.len(), candidates));
        }

        // let args be candidates with "=", unless they are in the input line already.
        // If the arg is declared as multi, show it regardless since it may appear multiple times
        for arg in &node.args {
            if arg.name.starts_with(last) && (!input.contains(&arg.name) || arg.multi) {
                candidates.push(arg.name.clone() + "=");
            }
        }

        // offer children nodes
        for c in node.children.values() {
            if c.name.starts_with(last) {
                candidates.push(c.name.clone());
            }
        }

        Ok((pos - last.len(), candidates))
    }
}
