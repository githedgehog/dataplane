// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control channel for the router

use mio::Interest;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender as AsyncSender;
use tokio::task;
#[allow(unused)]
use tracing::{debug, error, info, warn};

use crate::RouterError;
use crate::config::RouterConfig;
use crate::rio::{CPSOCK, Rio};
use crate::routingdb::RoutingDb;

pub(crate) type RouterCtlReplyTx = AsyncSender<Result<(), RouterError>>;

#[repr(transparent)]
pub struct LockGuard(Option<Sender<RouterCtlMsg>>);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let tx = self.0.take();
        if let Some(tx) = tx {
            task::spawn(async move {
                if let Err(e) = tx.send(RouterCtlMsg::GuardedUnlock).await {
                    error!("Fatal: could not send unlock request!!: {e}");
                }
            });
        }
    }
}

pub enum RouterCtlMsg {
    Finish,
    Lock(RouterCtlReplyTx),
    Unlock(RouterCtlReplyTx),
    GuardedUnlock,
    Configure(RouterConfig, RouterCtlReplyTx),
}

// An object to send control messages to the router
pub struct RouterCtlSender(tokio::sync::mpsc::Sender<RouterCtlMsg>);
impl RouterCtlSender {
    pub(crate) fn new(tx: Sender<RouterCtlMsg>) -> Self {
        Self(tx)
    }
    pub(crate) fn as_lock_guard(&self) -> LockGuard {
        LockGuard(Some(self.0.clone()))
    }
    #[must_use]
    pub async fn lock(&mut self) -> Result<LockGuard, RouterError> {
        debug!("Requesting CPI lock...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::Lock(reply_tx);
        self.0
            .send(msg)
            .await
            .map_err(|_| RouterError::Internal("Failed to send lock request"))?;
        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive lock reply"))?;
        reply?;
        Ok(self.as_lock_guard())
    }
    #[allow(unused)]
    #[must_use]
    pub async fn unlock(&mut self) -> Result<(), RouterError> {
        debug!("Requesting CPI lock...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::Unlock(reply_tx);
        self.0
            .send(msg)
            .await
            .map_err(|_| RouterError::Internal("Failed to send unlock request"))?;
        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive unlock reply"))?;
        reply?;
        Ok(())
    }
    pub async fn configure(&mut self, config: RouterConfig) -> Result<(), RouterError> {
        let genid = config.genid();
        debug!("Requesting router to apply config for gen {genid}...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::Configure(config, reply_tx);
        self.0
            .send(msg)
            .await
            .map_err(|_| RouterError::Internal("Failed to send configure request"))?;
        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive configure reply"))?;
        reply?;
        Ok(())
    }
}

/// Handle a lock request for the indicated CPI
fn handle_lock(rio: &mut Rio, lock: bool, reply_to: Option<RouterCtlReplyTx>) {
    let action = if lock { "lock" } else { "unlock" };
    let interests = if lock {
        rio.frozen = true;
        Interest::WRITABLE
    } else {
        rio.frozen = false;
        Interest::WRITABLE | Interest::READABLE
    };
    let result = rio.reregister(CPSOCK, rio.cpi_sock.get_raw_fd(), interests);
    if result.is_ok() {
        debug!("The CPI is now {action}ed");
    } else {
        error!("Failed to {action} CPI");
    }

    if let Some(reply_to) = reply_to {
        if let Err(e) = reply_to.send(result) {
            error!("Fatal: could not reply to lock/unlock request: {e:?}");
        }
    }
}

/// Handle a configure request. This function applies the configuration that
/// pertains to the router and that of FRR if provided.
fn handle_configure(
    rio: &mut Rio,
    config: RouterConfig,
    db: &mut RoutingDb,
    reply_to: RouterCtlReplyTx,
) {
    /* apply router config */
    let result = config.apply(db);
    if result.is_err() {
        let _ = reply_to.send(result).map_err(|e| {
            error!("Fatal: could not reply to configure request: {e:?}");
        });
        return;
    }

    /* request application of frr config */
    if let Some(frr_config) = config.get_frr_config() {
        rio.request_frr_config(config.genid(), frr_config.clone());
    }

    /* reply */
    let _ = reply_to.send(result).map_err(|e| {
        error!("Fatal: could not reply to configure request: {e:?}");
    });

    /* store the config */
    db.set_config(config);
}

/// Handle a request from the control channel
pub(crate) fn handle_ctl_msg(rio: &mut Rio, db: &mut RoutingDb) {
    match rio.ctl_rx.try_recv() {
        Ok(RouterCtlMsg::Finish) => {
            info!("Got request to shutdown. Au revoir ...");
            rio.run = false;
        }
        Ok(RouterCtlMsg::Lock(reply_to)) => handle_lock(rio, true, Some(reply_to)),
        Ok(RouterCtlMsg::Unlock(reply_to)) => handle_lock(rio, false, Some(reply_to)),
        Ok(RouterCtlMsg::GuardedUnlock) => handle_lock(rio, false, None),
        Ok(RouterCtlMsg::Configure(config, reply_to)) => {
            handle_configure(rio, config, db, reply_to)
        }
        Err(TryRecvError::Empty) => {}
        Err(e) => {
            error!("Error receiving from ctl channel {e:?}");
        }
    }
}
