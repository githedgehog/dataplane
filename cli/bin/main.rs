// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds main parser for command arguments

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::collapsible_if)]

use argsparse::{ArgsError, CliArgs};
use clap::Parser;
use cmdline::Cmdline;
use cmdtree::Node;
use cmdtree_dp::gw_cmd_tree;
use colored::Colorize;
use dataplane_cli::cliproto::CliLocalError;
use dataplane_cli::cliproto::{CliAction, CliRequest, CliResponse};
use std::io::stdin;
use std::os::unix::net::UnixDatagram;
use std::rc::Rc;
use terminal::{TermInput, Terminal};

mod argsparse;
mod cmdline;
mod cmdtree;
mod cmdtree_dp;
mod completions;
mod terminal;

#[rustfmt::skip]
fn greetings() {
    println!("\n{}.", "Gateway dataplane CLI".bright_white().bold());
    println!("© 2025 Hedgehog Open Network Fabric.\n");
}

#[allow(unused)]
fn ask_user(question: &str) -> bool {
    let mut answer = String::new();
    loop {
        println!("{question}");
        answer.truncate(0);
        let _ = stdin().read_line(&mut answer);
        if let Some('\n') = answer.chars().next_back() {
            answer.pop();
        }
        if let Some('\r') = answer.chars().next_back() {
            answer.pop();
        }
        match answer.to_lowercase().as_str() {
            "yes" => return true,
            "no" => return false,
            _ => {}
        }
    }
}

/// Receive the response, synchronously. This is blocking by design
fn process_cli_response(sock: &UnixDatagram) -> Result<String, String> {
    let response = CliResponse::recv_sync(sock).map_err(|e| e.to_string())?;
    match response.result {
        Ok(data) => Ok(data),
        Err(e) => Err(format!("Dataplane answered: {e}")),
    }
}

fn execute_remote_action(
    action: CliAction,       // action to perform
    args: &CliArgs,          // action arguments
    terminal: &mut Terminal, // this terminal
) {
    if !terminal.is_connected() {
        print_err!("Not connnected to dataplane.");
        return;
    }
    // build request
    let request = CliRequest::new(action, args.remote.clone());

    // serialize it and send it
    if let Err(e) = request.send(&terminal.sock) {
        print_err!("Error issuing request: {e}");
        if matches!(e, CliLocalError::IoError(_)) {
            terminal.connected(false);
        }
        return;
    }

    // receive and deserialize response, synchronously
    match process_cli_response(&terminal.sock) {
        Ok(data) => println!("{data}"),
        Err(e) => print_err!("{e}"),
    }
}

fn execute_action(
    action: CliAction, // action to perform
    args: &CliArgs,    // action arguments
    cmdline: &Cmdline,
    terminal: &mut Terminal, // this terminal
) {
    match action {
        CliAction::Clear => terminal.clear(),
        CliAction::Quit => terminal.stop(),
        CliAction::Help => terminal.get_cmd_tree().dump(),
        CliAction::Disconnect => terminal.disconnect(),
        CliAction::Connect => {
            let path = args
                .connpath
                .clone()
                .unwrap_or_else(|| cmdline.path.clone());

            let bind_addr = args
                .bind_address
                .clone()
                .unwrap_or_else(|| cmdline.bind_address.clone());
            terminal.connect(&bind_addr, &path);
        }
        // all others are remote
        _ => execute_remote_action(action, args, terminal),
    }
}

fn show_bad_arg(input_line: &str, argname: &str) {
    if let Some((good, _bad)) = input_line.split_once(argname) {
        println!(" {}{} {}", good, argname.red(), "??".red());
    }
}

/// Build arguments from map of arguments
fn process_args(input: &TermInput) -> Result<CliArgs, ()> {
    let args = CliArgs::from_args_map(input.get_args().clone());
    match args {
        Err(ArgsError::UnrecognizedArgs(args_map)) => {
            print_err!(" Unrecognized arguments");
            for arg in args_map.keys() {
                show_bad_arg(input.get_line(), arg);
            }
            Err(())
        }
        Err(e) => {
            print_err!(" {}", e);
            Err(())
        }
        Ok(args) => Ok(args),
    }
}

fn process_command(
    terminal: &mut Terminal,
    cmds: &Rc<Node>,
    cmdline: &Cmdline,
    input: &mut TermInput,
) {
    if let Some(node) = cmds.find_best(input.get_tokens()) {
        if let Some(action) = &node.action {
            if let Ok(args) = process_args(input) {
                execute_action(*action, &args, cmdline, terminal);
            }
        } else if node.depth > 0 {
            print_err!("No action associated to command");
            if node.children.is_empty() {
                print_err!("Command is not implemented");
            } else {
                print_err!("Options are:");
                node.show_children();
            }
        } else {
            print_err!("syntax error");
        }
    }
}

fn proc_cmdline_commands(
    terminal: &mut Terminal,
    cmds: &Rc<Node>,
    cmdline: &Cmdline,
    input_cmds: &Vec<String>,
) {
    terminal.connect(&cmdline.bind_address, &cmdline.path);
    if !terminal.is_connected() {
        println!("Failed to connect to dataplane");
        return;
    }
    for cmd in input_cmds {
        if let Some(mut input) = terminal.proc_line(cmd) {
            println!("{}{}", terminal.read_prompt(), input.get_line());
            process_command(terminal, cmds, cmdline, &mut input);
        }
    }
}

fn main() {
    // parse cmd line
    let cmdline = cmdline::Cmdline::parse();

    // build command tree
    let cmdtree = Rc::new(gw_cmd_tree());
    let mut terminal = Terminal::new("dataplane", &cmdtree);

    // if a command is specified, handle it and exit
    if !cmdline.command.is_empty() {
        proc_cmdline_commands(&mut terminal, &cmdtree, &cmdline, &cmdline.command);
        return;
    }

    terminal.clear();
    greetings();

    terminal.connect(&cmdline.bind_address, &cmdline.path);

    // infinite loop until user quits
    while terminal.runs() {
        let mut input = terminal.prompt();
        if !terminal.is_connected() {
            terminal.connect(&cmdline.bind_address, &cmdline.path);
        }
        // don't process input if it starts with # ... but keep it in history
        if !input.get_line().starts_with('#') {
            process_command(&mut terminal, &cmdtree, &cmdline, &mut input);
        }
        terminal.add_history_entry(input.get_line().to_owned());
    }
}
