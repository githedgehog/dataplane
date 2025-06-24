// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control channel for the CPI

use mio::Interest;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender as AsyncSender;
use tokio::task;
#[allow(unused)]
use tracing::{debug, error, info, warn};

use crate::cpi::{CPSOCK, Cpi};
use crate::routingdb::RoutingDb;
use crate::{RouterError, config::RouterConfig};
use mio::unix::SourceFd;

type CpiCtlReplyTx = AsyncSender<Result<(), RouterError>>;

#[repr(transparent)]
pub struct LockGuard(Option<Sender<CpiCtlMsg>>);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let tx = self.0.take();
        if let Some(tx) = tx {
            task::spawn(async move {
                if let Err(e) = tx.send(CpiCtlMsg::GuardedUnlock).await {
                    error!("Fatal: could not send unlock request!!: {e}");
                }
            });
        }
    }
}

pub enum CpiCtlMsg {
    Finish,
    Lock(CpiCtlReplyTx),
    Unlock(CpiCtlReplyTx),
    GuardedUnlock,
    Configure(RouterConfig, CpiCtlReplyTx),
}

// An object to send control messages to the cpi/router
pub struct RouterCtlSender(tokio::sync::mpsc::Sender<CpiCtlMsg>);
impl RouterCtlSender {
    pub(crate) fn new(tx: Sender<CpiCtlMsg>) -> Self {
        Self(tx)
    }
    pub(crate) fn as_lock_guard(&self) -> LockGuard {
        LockGuard(Some(self.0.clone()))
    }
    #[must_use]
    pub async fn lock(&mut self) -> Result<LockGuard, RouterError> {
        debug!("Requesting CPI lock...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = CpiCtlMsg::Lock(reply_tx);
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
        let msg = CpiCtlMsg::Unlock(reply_tx);
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
        debug!("Requesting router to apply configuration...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = CpiCtlMsg::Configure(config, reply_tx);
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
fn handle_lock(cpi: &mut Cpi, lock: bool, reply_to: Option<CpiCtlReplyTx>) {
    let action = if lock { "lock" } else { "unlock" };
    let interests = if lock {
        cpi.frozen = true;
        Interest::WRITABLE
    } else {
        cpi.frozen = false;
        Interest::WRITABLE | Interest::READABLE
    };
    let result = cpi
        .poller
        .registry()
        .reregister(
            &mut SourceFd(&cpi.cached_sock.get_raw_fd()),
            CPSOCK,
            interests,
        )
        .map_err(|_| RouterError::Internal("(un)-locking failed"));

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

/// Handle a configure request and reply with the result
fn handle_configure(config: RouterConfig, db: &mut RoutingDb, reply_to: CpiCtlReplyTx) {
    let result = config.apply(db);
    if let Err(e) = reply_to.send(result) {
        error!("Fatal: could not reply to configure request: {e:?}");
    } else {
        debug!("Replied to configure request");
        db.set_config(config);
    }
}

/// Handle a request from the control channel
pub(crate) fn handle_ctl_msg(cpi: &mut Cpi, db: &mut RoutingDb) {
    match cpi.ctl_rx.try_recv() {
        Ok(CpiCtlMsg::Finish) => {
            info!("Got request to shutdown. Au revoir ...");
            cpi.run = false;
        }
        Ok(CpiCtlMsg::Lock(reply_to)) => handle_lock(cpi, true, Some(reply_to)),
        Ok(CpiCtlMsg::Unlock(reply_to)) => handle_lock(cpi, false, Some(reply_to)),
        Ok(CpiCtlMsg::GuardedUnlock) => handle_lock(cpi, false, None),
        Ok(CpiCtlMsg::Configure(config, reply_to)) => handle_configure(config, db, reply_to),
        Err(TryRecvError::Empty) => {}
        Err(e) => {
            error!("Error receiving from ctl channel {e:?}");
        }
    }
}
