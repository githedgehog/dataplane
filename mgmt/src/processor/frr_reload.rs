// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Wrapper for the FRR reload utility (frr_reload.py).

use std::process::{Command, Stdio};
use tracing::info;

#[allow(dead_code)]
pub fn reload_frr(
    frr_reload_bin: &str,
    frr_config_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    frr_test_config(frr_reload_bin, frr_config_file)?;
    frr_do_reload(frr_reload_bin, frr_config_file)?;

    info!("FRR successfully reloaded");
    Ok(())
}

fn frr_test_config(
    frr_reload_bin: &str,
    frr_config_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_frr_reload_script(frr_reload_bin, frr_config_file, &["--test"])
}

fn frr_do_reload(
    frr_reload_bin: &str,
    frr_config_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_frr_reload_script(
        frr_reload_bin,
        frr_config_file,
        &["--reload", "--overwrite"],
    )
}

fn run_frr_reload_script(
    frr_reload_bin: &str,
    frr_config_file: &str,
    action_args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(frr_reload_bin)
        .args(action_args)
        .arg(frr_config_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn command: {}", e))?
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for command: {}", e))?;

    if !output.stderr.is_empty() {
        return Err(format!(
            "Command printed an error message. Command status: {}, stdout: {}, stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    if !output.status.success() {
        return Err(format!(
            "Command exited with non-zero status. Command status: {}, stdout: {}, stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRR_CONFIG: &str = "/etc/frr/frr.conf";

    fn binpath(name: &str) -> String {
        let test_path: &str = "mgmt/src/processor/frr_reload_test";
        format!("{test_path}/{name}")
    }

    #[test]
    fn test_reload_frr() {
        let bin = binpath("pass.sh");
        let result = reload_frr(bin.as_str(), FRR_CONFIG);
        assert!(
            result.is_ok(),
            "FRR reload test failed: {:?} (bin: {bin})",
            result
        );
    }

    #[test]
    fn test_reload_frr_fail_errcode() {
        let result = frr_do_reload(binpath("fail-errcode.sh").as_str(), FRR_CONFIG);
        assert!(
            result.is_err(),
            "FRR config test succeeded unexpectedly: {:?}",
            result
        );
        assert_eq!(
            result.map_err(|e| e.to_string()),
            Err("Command exited with non-zero status. Command status: exit status: 1, stdout: , stderr: "
                .to_string())
        );
    }

    #[test]
    fn test_reload_frr_fail_stderr() {
        let result = frr_do_reload(binpath("fail-stderr.sh").as_str(), FRR_CONFIG);
        assert!(
            result.is_err(),
            "FRR cofig test succeeded unexpectedly: {:?}",
            result
        );
        assert_eq!(
            result.map_err(|e| e.to_string()),
            Err("Command printed an error message. Command status: exit status: 0, stdout: , stderr: failure\n"
                .to_string())
        );
    }

    #[test]
    fn test_reload_frr_errcode_stderr() {
        let result = frr_do_reload(binpath("fail-errcode-stderr.sh").as_str(), FRR_CONFIG);
        assert!(
            result.is_err(),
            "FRR cofig test succeeded unexpectedly: {:?}",
            result
        );
        assert_eq!(
            result.map_err(|e| e.to_string()),
            Err("Command printed an error message. Command status: exit status: 1, stdout: , stderr: failure\n"
                .to_string())
        );
    }
}
