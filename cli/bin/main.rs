// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adds main parser for command arguments

use argsparse::{ArgsError, CliArgs};
use cmdtree_dp::gw_cmd_tree;
use colored::Colorize;
use dataplane_cli::cliproto::{CliAction, CliRequest, CliResponse, CliSerialize};
use std::collections::HashMap;
use std::io::stdin;
use std::os::unix::net::UnixDatagram;
use std::rc::Rc;
use terminal::Terminal;

pub mod argsparse;
pub mod cmdtree;
pub mod cmdtree_dp;
pub mod completions;
pub mod terminal;

const DEFAULT_CLI_BIND: &str = "/tmp/cli.sock";
const DEFAULT_DATAPLANE_PATH: &str = "/tmp/dataplane_ctl.sock";

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
        };
    }
}

/// Receive the response, synchronously. This function may block the caller,
/// which is the desired behavior. Now, unfortunately the peek() and the like
/// methods of UnixDatagram are not stable. This creates an issue because if
/// a message has length L and we request to read fewer octets, the excess ones
/// will be lost. We could request a very large L, but that would require
/// allocating a big buffer (no big deal), but its size could sooner or later be
/// exceeded (e.g. retrieving a full routing table).
/// We solve this for the moment by letting the dataplane send the size of the
/// message (as 8 octets|u64) and then the message itself, in two writes.
/// Therefore, here, we'll do 2 reads; one to figure out the length and a second
/// one to received the actual message (response).
fn process_cli_response(sock: &UnixDatagram) {
    let mut rx_buff = vec![0u8; 1024];
    let mut msg_size_wire = [0u8; 8];
    let msg_size: u64;

    if let Err(e) = sock.recv(msg_size_wire.as_mut()) {
        print_err!("Error receiving msg size: {e}");
        return;
    } else {
        msg_size = u64::from_ne_bytes(msg_size_wire);
        if msg_size as usize > rx_buff.capacity() {
            rx_buff.resize(msg_size as usize, 0);
        }
    }
    match sock.recv(rx_buff.as_mut_slice()) {
        Ok(rx_len) => match CliResponse::deserialize(&rx_buff[0..rx_len]) {
            Ok(response) => match &response.result {
                Ok(data) => println!("{data}"),
                Err(e) => print_err!("Dataplane error: {e}"),
            },
            Err(_) => print_err!("Failed to deserialize response"),
        },
        Err(e) => {
            print_err!("Failed to recv from dataplane: {e}");
        }
    }
}

fn execute_remote_action(
    action: CliAction,       // action to perform
    args: &CliArgs,          // action arguments
    terminal: &mut Terminal, // this terminal
) {
    // don't issue request if we're not connected to dataplane
    if !terminal.is_connected() {
        print_err!("Not connnected to dataplane.");
        return;
    }

    // serialize request and send it
    if let Ok(request) = CliRequest::new(action, args.remote.clone()).serialize() {
        match terminal.sock.send(&request) {
            Ok(_) => process_cli_response(&terminal.sock),
            Err(e) => {
                print_err!(
                    "Error sending request: {e}, request length: {}",
                    request.len()
                );
                terminal.connected(false);
            }
        }
    } else {
        print_err!("Failed to serialize request!");
    }
}

fn execute_action(
    action: u16,             // action to perform
    args: &CliArgs,          // action arguments
    terminal: &mut Terminal, // this terminal
) {
    let cli_action = action.try_into().expect("Bad action code");
    match cli_action {
        CliAction::Clear => terminal.clear(),
        CliAction::Quit => terminal.stop(),
        CliAction::Help => terminal.get_cmd_tree().dump(),
        CliAction::Disconnect => terminal.disconnect(),
        CliAction::Connect => {
            let path = args
                .connpath
                .clone()
                .unwrap_or_else(|| DEFAULT_DATAPLANE_PATH.to_owned());

            let bind_addr = args
                .bind_address
                .clone()
                .unwrap_or_else(|| DEFAULT_CLI_BIND.to_owned());
            terminal.connect(&bind_addr, &path);
        }
        // all others are remote
        _ => execute_remote_action(cli_action, args, terminal),
    }
}

/// Build a map of arguments from line input by user
fn get_args(line: &str) -> HashMap<String, String> {
    let mut args = HashMap::new();
    let mut token_args: Vec<&str> = line.split_whitespace().collect();
    token_args = token_args
        .iter()
        .filter(|token| token.contains("="))
        .cloned()
        .collect();
    for targ in token_args.iter() {
        if let Some((arg, arg_value)) = targ.split_once("=") {
            args.insert(arg.to_owned(), arg_value.to_owned());
        }
    }
    args
}

fn show_bad_arg(input_line: &str, argname: &str) {
    if let Some((good, _bad)) = input_line.split_once(argname) {
        println!(" {}{} {}", good, argname.red(), "??".red());
    }
}

/// Build arguments from map of arguments
fn process_args(input_line: &str) -> Result<CliArgs, ()> {
    let args_map = get_args(input_line);
    let args = CliArgs::from_args_map(args_map);
    match args {
        Err(ArgsError::UnrecognizedArgs(args_map)) => {
            print_err!(" Unrecognized arguments");
            for (arg, _value) in args_map.iter() {
                show_bad_arg(input_line, arg);
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

fn main() {
    // build command tree
    let cmds = Rc::new(gw_cmd_tree());
    let mut terminal = Terminal::new("dataplane", cmds.clone());
    terminal.clear();

    // be polite
    greetings();

    // infinite loop until user quits
    while terminal.runs() {
        let mut bad_syntax = false;
        let mut input = terminal.prompt();
        if let Some(node) = cmds.find_best(input.get_tokens()) {
            if let Some(action) = &node.action {
                if let Ok(args) = process_args(input.get_line()) {
                    execute_action(*action, &args, &mut terminal);
                }
            } else if node.depth > 0 {
                print_err!("No action associated to command");
                if !node.children.is_empty() {
                    print_err!("Options are:");
                    node.show_children();
                } else {
                    print_err!("Command is not implemented");
                }
            } else {
                print_err!("syntax error");
                bad_syntax = true;
            }
        }
        if !bad_syntax || input.get_line().starts_with("#") {
            terminal.add_history_entry(input.get_line().to_owned());
        }
    }
}
