// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds command completions

use crate::cmdtree::Node;
use reedline::{Completer, Span, Suggestion};
use std::sync::Arc;

#[derive(Default)]
pub struct CmdCompleter {
    cmdtree: Arc<Node>,
}
#[allow(unused)]
impl CmdCompleter {
    pub fn new(cmdtree: Arc<Node>) -> Self {
        Self { cmdtree }
    }
    #[allow(unused)]
    pub fn get_commands(&self) -> &Node {
        &self.cmdtree
    }
}

fn suggestion(value: String, span: Span) -> Suggestion {
    Suggestion {
        value,
        description: None,
        style: None,
        extra: None,
        span,
        append_whitespace: false,
        display_override: None,
        match_indices: None,
    }
}

impl Completer for CmdCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
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
                return Vec::new();
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
                    let span = Span::new(pos - value.len(), pos);
                    return candidates
                        .into_iter()
                        .map(|c| suggestion(c, span))
                        .collect();
                }
            }
            let span = Span::new(pos - last.len(), pos);
            return candidates
                .into_iter()
                .map(|c| suggestion(c, span))
                .collect();
        }

        let span = Span::new(pos - last.len(), pos);

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

        candidates
            .into_iter()
            .map(|c| suggestion(c, span))
            .collect()
    }
}
