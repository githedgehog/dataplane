// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Defines a command tree of Nodes

use colored::Colorize;
use std::collections::BTreeMap;
use std::collections::VecDeque;

#[derive(Clone, Default, Debug)]
pub struct NodeArg {
    pub name: String,
    pub choices: Vec<String>,
}

#[allow(unused)]
impl NodeArg {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            choices: Vec::new(),
        }
    }
    pub fn choice(mut self, choice: &str) -> Self {
        self.choices.push(choice.to_owned());
        self
    }
    pub fn add_choice(&mut self, choice: &str) {
        self.choices.push(choice.to_owned());
    }
}

#[derive(Default)]
pub struct Node {
    pub(crate) name: String,
    pub depth: u16,
    pub children: BTreeMap<String, Node>,
    pub(crate) description: Option<&'static str>,
    pub action: Option<u16>,
    pub(crate) args: Vec<NodeArg>,
    pub(crate) hidden: bool,
}
#[allow(unused)]
impl Node {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            hidden: false,
            ..Default::default()
        }
    }
    pub fn action(mut self, action: u16) -> Self {
        self.action = Some(action);
        self
    }
    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(NodeArg::new(arg));
        self
    }
    pub fn arg_add(mut self, arg: NodeArg) -> Self {
        self.args.push(arg);
        self
    }
    pub fn find_arg(&self, name: &str) -> Option<&NodeArg> {
        self.args.iter().find(|&arg| arg.name == name)
    }
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }
    pub fn desc(mut self, description: &'static str) -> Self {
        self.description = Some(description);
        self
    }
    fn set_depth(&mut self, depth: u16) {
        self.depth = depth;
        self.children
            .values_mut()
            .for_each(|c| c.set_depth(depth + 1));
    }
    fn add(&mut self, mut cmd: Node) {
        if cmd.name.is_empty() {
            //if a node has no name, skip it and adopt
            //its children. This is just to ease the
            //creation of the tree by creating
            //unnamed commands that will not show up
            cmd.set_depth(self.depth);
            for child in cmd.children.into_values() {
                self.children.insert(child.name.to_owned(), child);
            }
        } else {
            cmd.set_depth(self.depth + 1);
            self.children.insert(cmd.name.to_owned(), cmd);
        }
    }

    // lookup a node in the cmd tree from the vector of tokens.
    // Matched tokens are stored in matched vector.
    // Returns the last matched cmd node. So, if tokens remain
    // that means that there was no full match. This is used for
    // the command completion.
    pub(crate) fn lookup<'a>(
        &self,
        tokens: &mut VecDeque<&'a str>,
        matched: &mut VecDeque<&'a str>,
    ) -> &Self {
        if let Some(word) = tokens.pop_front() {
            match self.children.get(word) {
                Some(child) => {
                    matched.push_back(word);
                    child.lookup(tokens, matched)
                }
                None => {
                    // put the non-matched word back
                    tokens.push_front(word);
                    self
                }
            }
        } else {
            self
        }
    }
    pub fn find_best(&self, tokens: &mut VecDeque<String>) -> Option<&Self> {
        if let Some(word) = tokens.pop_front() {
            match self.children.get(word.as_str()) {
                Some(child) => child.find_best(tokens),
                None => Some(self),
            }
        } else {
            Some(self)
        }
    }
    pub fn show_children(&self) {
        self.children
            .values()
            .filter(|child| !child.hidden)
            .for_each(|child| println!(" {}", child.name.yellow()));
    }

    pub fn dump(&self) {
        if self.depth == 0 {
            println!("\n {}", " ━━━ Commands ━━━".bold());
        }
        let indent = "    ".repeat(self.depth as usize);
        if !self.hidden {
            if self.depth == 1 {
                print!("{} {}", indent, self.name.bold().white());
            } else {
                print!("{} {}", indent, self.name);
            }
            self.args.iter().for_each(|arg| {
                print!(" @{}", arg.name);
                if !arg.choices.is_empty() {
                    print!("{}", "=[".yellow());
                    arg.choices
                        .iter()
                        .for_each(|choice| print!(" {}", choice.yellow()));
                    print!("{}", " ]".yellow());
                }
            });

            if let Some(descr) = self.description {
                print!(" {}", descr.italic().dimmed());
            }
            println!();
        }
        for c in self.children.values() {
            c.dump();
        }

        if self.depth == 0 || (self.depth == 1 && !self.children.is_empty()) {
            println!();
        }
    }
}

use std::ops::AddAssign;
impl AddAssign for Node {
    fn add_assign(&mut self, rhs: Self) {
        self.add(rhs);
    }
}
