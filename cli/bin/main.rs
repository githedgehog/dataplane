// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds main parser for command arguments

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::collapsible_if)]

use crate::argsparse::{ArgsError, CliArgs};
use crate::filters::filter_output;
use clap::Parser;
use cmdline::Cmdline;
use cmdtree::Node;
use cmdtree_dp::gw_cmd_tree;
use colored::Colorize;
use concurrency::sync::Arc;
use dataplane_cli::cliproto::CliLocalError;
use dataplane_cli::cliproto::{CliAction, CliError, CliRequest, CliResponse};
use std::io::stdin;
use terminal::{TermInput, Terminal};

mod argsparse;
mod cmdline;
mod cmdtree;
mod cmdtree_dp;
mod completions;
mod filters;
mod prefetch;
mod terminal;

#[rustfmt::skip]
fn greetings() {
    println!("\n{}.", "Gateway dataplane CLI".bright_white().bold());
    println!("© 2025 Hedgehog Open Network Fabric.\n");
}

/// The type of errors that can happen in the cli client
#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("Not connected to dataplane")]
    NotConnected,

    #[error("Communication error: {0}")]
    Communication(#[from] CliLocalError),

    #[error("Dataplane: {0}")]
    Remote(#[from] CliError),

    #[error("{0}")]
    Args(#[from] ArgsError),

    #[error("Syntax error: {0}")]
    SyntaxError(String),

    #[error("Incomplete command: {0}")]
    IncompleteCommand(String),

    #[error("Not implemented")]
    NotImplemented,
}

#[allow(unused)]
fn ask_user(question: &str) -> bool {
    let mut answer = String::new();
    loop {
        println!("{question}");
        answer.clear();
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

fn execute_remote_action(
    action: CliAction,
    args: &CliArgs,
    terminal: &Terminal,
) -> Result<CliResponse, ClientError> {
    let mut session = terminal.session.lock();
    let Some(sock) = session.sock() else {
        return Err(ClientError::NotConnected);
    };

    // build request and send it
    let request = CliRequest::new(action, args.remote.clone());
    if let Err(e) = request.send(sock) {
        print_err!("Error issuing request: {e}");
        if matches!(e, CliLocalError::IoError(_)) {
            session.disconnect();
        }
        return Err(e.into());
    }
    // receive the response (this is blocking by design)
    CliResponse::recv_sync(sock).map_err(Into::into)
}

fn connect(terminal: &mut Terminal, cmdline: &Cmdline, args: &CliArgs) {
    let remote_addr = args.connpath.as_ref().unwrap_or(&cmdline.path);
    let local_addr = args.bind_address.as_ref().unwrap_or(&cmdline.bind_address);
    terminal.connect(local_addr, remote_addr);
}

fn execute_action(
    action: CliAction, // action to perform
    args: &CliArgs,    // action arguments
    cmdline: &Cmdline,
    terminal: &mut Terminal, // this terminal
) -> Result<Option<CliResponse>, ClientError> {
    if action.is_local() {
        // local commands do not issue requests and don't return `CliResponse`s
        match action {
            CliAction::Clear => terminal.clear(),
            CliAction::Quit => terminal.stop(),
            CliAction::Help => terminal.get_cmd_tree().dump(),
            CliAction::Disconnect => terminal.disconnect(),
            CliAction::Connect => connect(terminal, cmdline, args),
            _ => unreachable!(),
        }
        return Ok(None);
    }
    let response = execute_remote_action(action, args, terminal)?;
    Ok(Some(response))
}

/// Build arguments from map of arguments
fn process_args(input: &TermInput) -> Result<CliArgs, ArgsError> {
    CliArgs::from_args_map(input.get_args()).inspect_err(|e| print_err!(" {e}"))
}

fn process_command(
    terminal: &mut Terminal,
    cmds: &Arc<Node>,
    cmdline: &Cmdline,
    input: &TermInput,
) -> Result<Option<CliResponse>, ClientError> {
    let node = cmds.find_best(input.get_tokens());
    if let Some(action) = &node.action {
        let args = process_args(input)?;
        execute_action(*action, &args, cmdline, terminal)
    } else if node.depth > 0 {
        if node.children.is_empty() {
            Err(ClientError::NotImplemented)
        } else {
            print_err!("Incomplete command. Options are:");
            node.show_children();
            Err(ClientError::IncompleteCommand(input.get_line().to_owned()))
        }
    } else {
        Err(ClientError::SyntaxError(input.get_line().to_owned()))
    }
}

fn proc_cmdline_commands(
    terminal: &mut Terminal,
    cmds: &Arc<Node>,
    cmdline: &Cmdline,
    input_cmds: &Vec<String>,
) -> bool {
    terminal.connect(&cmdline.bind_address, &cmdline.path);
    if !terminal.is_connected() {
        println!("Failed to connect to dataplane");
        return true;
    }
    let mut errors = 0;
    for cmd in input_cmds {
        if let Some(input) = Terminal::proc_line(cmd) {
            println!("{}{}", terminal.read_prompt(), input.get_line());
            let outcome = process_command(terminal, cmds, cmdline, &input);
            if process_outcome(outcome, &input).is_err() {
                errors += 1;
            }
        }
    }
    errors > 0
}

// Process the outcome of the command (just printing atm) and
// return whether there was an error, local or remote.
fn process_outcome(
    outcome: Result<Option<CliResponse>, ClientError>,
    input: &TermInput,
) -> Result<(), ClientError> {
    match outcome {
        Ok(opt_response) => match opt_response {
            Some(response) => match response.result {
                Ok(out) => {
                    let display = filter_output(&out, input.get_filters());
                    println!("{display}");
                    Ok(())
                }
                Err(e) => {
                    print_err!("{e}");
                    Err(e.into())
                }
            },
            None => Ok(()), // local command
        },
        Err(e) => {
            print_err!("{e}");
            Err(e)
        }
    }
}

fn main() {
    // build command tree
    let cmdtree = Arc::new(gw_cmd_tree());
    let mut terminal = Terminal::new("dataplane", &cmdtree);

    // parse cmd line
    let cmdline = cmdline::Cmdline::parse();

    // if non-interactive commands are specified, handle them and exit
    if !cmdline.command.is_empty() {
        let failures = proc_cmdline_commands(&mut terminal, &cmdtree, &cmdline, &cmdline.command);
        terminal.disconnect();
        std::process::exit(i32::from(failures));
    }

    terminal.clear();
    greetings();

    terminal.connect(&cmdline.bind_address, &cmdline.path);

    // infinite loop until user quits
    while terminal.runs() {
        let input = terminal.prompt();
        if !terminal.runs() {
            break;
        }
        if !terminal.is_connected() {
            terminal.connect(&cmdline.bind_address, &cmdline.path);
        }
        if !input.get_line().starts_with('#') {
            // process the command
            let outcome = process_command(&mut terminal, &cmdtree, &cmdline, &input);
            let _ = process_outcome(outcome, &input);
        }
    }
}
