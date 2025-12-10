// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use tokio::sync::mpsc::Sender;

use crate::processor::proc::ConfigChannelRequest;

#[derive(Debug, thiserror::Error)]
pub enum K8sClientError {
    // Define error variants here
}

pub async fn k8s_start_client(_tx: Sender<ConfigChannelRequest>) -> Result<(), K8sClientError> {
    unimplemented!()
}
