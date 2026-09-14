// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Prefetching of autocompletion data. The CLI sends prefetch requests
//! to get vectors of strings used for auto-completion suggestions. A
//! selector is used to indicate the type of identifiers that are needed.
//! E.g. to autocomplete vpc names, a `PrefetchSelector` of `Vpcs` is used
//! which will cause dataplane to provide `PrefetchedData` with vpc names.
//! This is used for autocompletion.

use crate::CliResponse;
use dataplane_cli::cliproto::{CliAction, CliRequest, RequestArgs};
use dataplane_cli::cliproto::{PrefetchSelector, PrefetchedData};
use std::os::unix::net::UnixDatagram;

/// Send a prefetch request. `PrefetchSelector` indicates the type of data to prefetch.
fn do_prefetch(sock: &UnixDatagram, selector: PrefetchSelector) -> Option<PrefetchedData> {
    let args = RequestArgs::with_selector(selector);
    let request = CliRequest::new(CliAction::Prefetch, args);
    if request.send(sock).is_err() {
        return None;
    }
    CliResponse::recv_sync(sock)
        .ok()
        .map(|response| response.prefetched)
}

/// Send a prefetch request and pull the vectors out of the `PrefetchedData` in the response
pub fn prefetch(sock: &UnixDatagram, selector: PrefetchSelector) -> Vec<String> {
    do_prefetch(sock, selector)
        .map(|prefetched| prefetched.data)
        .unwrap_or_default()
}
