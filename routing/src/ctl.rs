// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control channel for the CPI

use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};

use crate::evpn::Vtep;
use crate::routingdb::RoutingDb;

pub enum CpiCtlMsg {
    Finish,
    SetVtep(Vtep),
}

// An object to send control messages to the cpi/router
pub struct RouterCtlSender(tokio::sync::mpsc::Sender<CpiCtlMsg>);
impl RouterCtlSender {
    pub(crate) fn new(tx: Sender<CpiCtlMsg>) -> Self {
        Self(tx)
    }
    pub async fn set_vtep(&mut self, vtep: Vtep) {
        if let Err(e) = self.0.send(CpiCtlMsg::SetVtep(vtep)).await {
            error!("Failed to send vtep data: {e} !");
        }
    }
}

/// Handle a control request to set the VTEP ip address and MAC
fn set_vtep(db: &mut RoutingDb, vtep_data: &Vtep) {
    let vtep = &mut db.vtep;

    if let Some(ip) = vtep_data.get_ip() {
        vtep.set_ip(ip);
        info!("VTEP ip address set to {ip}");
    } else {
        warn!("VTEP no longer has ip address");
        vtep.unset_ip();
    }
    if let Some(mac) = vtep_data.get_mac() {
        vtep.set_mac(mac);
        info!("VTEP mac address set to {mac}");
    } else {
        warn!("VTEP no longer has mac address");
        vtep.unset_mac();
    }
}

/// Handle a request from the control channel
pub(crate) fn handle_ctl_msg(rx: &mut Receiver<CpiCtlMsg>, run: &mut bool, db: &mut RoutingDb) {
    match rx.try_recv() {
        Ok(CpiCtlMsg::Finish) => {
            info!("Got request to shutdown. Au revoir ...");
            *run = false;
        }
        Ok(CpiCtlMsg::SetVtep(vtep_data)) => set_vtep(db, &vtep_data),
        Err(TryRecvError::Empty) => {}
        Err(e) => {
            error!("Error receiving from ctl channel {e:?}");
        }
    }
}
