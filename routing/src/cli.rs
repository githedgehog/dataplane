use crate::display::IfTableAddress;
use crate::display::{VrfV4Nexthops, VrfV6Nexthops, VrfViewV4, VrfViewV6};
use crate::routingdb::{RoutingDb, VrfTable};
use crate::vrf::{Route, RouteOrigin, Vrf, VrfId};
use crate::vrf::{RouteV4Filter, RouteV6Filter};
use cli::cliproto::{CliAction, CliError, CliRequest, CliResponse, CliSerialize, RouteProtocol};
use iptrie::{Ipv4Prefix, Ipv6Prefix};
use std::os::unix::net::SocketAddr;
use std::os::unix::net::UnixDatagram;
use tracing::{error, trace};

impl From<&RouteProtocol> for RouteOrigin {
    fn from(proto: &RouteProtocol) -> Self {
        match proto {
            RouteProtocol::Local => RouteOrigin::Local,
            RouteProtocol::Connected => RouteOrigin::Connected,
            RouteProtocol::Static => RouteOrigin::Static,
            RouteProtocol::Ospf => RouteOrigin::Ospf,
            RouteProtocol::Isis => RouteOrigin::Isis,
            RouteProtocol::Bgp => RouteOrigin::Bgp,
        }
    }
}

#[inline]
fn show_vrf_ipv4_routes(vrf: &Vrf, filter: &RouteV4Filter) -> String {
    /* This builds a view of the vrf, with only IPv4 routes
      and maybe not all of them, depending on the filter.
      If other serializations are needed, here we could either build also
      the view and implement serde on the view.
      Alternatively, call vrf.iter_v4() or vrf.filter_v4() to yield
      iterators over the (prefix, Routes).
    */

    let view = VrfViewV4 { vrf, filter };
    format!("{}", &view)
}

#[inline]
fn show_vrf_ipv6_routes(vrf: &Vrf, filter: &RouteV6Filter) -> String {
    let view = VrfViewV6 { vrf, filter };
    format!("{}", &view)
}

fn show_ipv4_routes_single_vrf(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: &RouteV4Filter,
) -> Result<CliResponse, CliError> {
    let out;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        if let Ok(vrf) = vrf.read() {
            out = show_vrf_ipv4_routes(&vrf, filter);
        } else {
            return Err(CliError::InternalError);
        }
    } else {
        return Err(CliError::NotFound(format!("No VRF with id {vrfid} exists")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ipv4_routes_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    filter: &RouteV4Filter,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        if let Ok(vrf) = vrf.read() {
            out += show_vrf_ipv4_routes(&vrf, filter).as_str();
        } else {
            out += "There was a problem retrieving routes";
        }
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ipv6_routes_single_vrf(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: RouteV6Filter,
) -> Result<CliResponse, CliError> {
    let out;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        if let Ok(vrf) = vrf.read() {
            out = show_vrf_ipv6_routes(&vrf, &filter);
        } else {
            return Err(CliError::InternalError);
        }
    } else {
        return Err(CliError::NotFound(format!("No VRF with id {vrfid} exists")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ipv6_routes_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    filter: &RouteV6Filter,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        if let Ok(vrf) = vrf.read() {
            out += show_vrf_ipv6_routes(&vrf, filter).as_str();
        } else {
            out += "There was a problem retrieving routes";
        }
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn route_filter_v4(request: &CliRequest) -> RouteV4Filter {
    let filter: RouteV4Filter = if let Some(protocol) = &request.args.protocol {
        let origin = RouteOrigin::from(protocol);
        Box::new(move |(_, route): &(&Ipv4Prefix, &Route)| route.origin == origin)
    } else {
        Box::new(|(_, _)| true)
    };
    filter
}
fn route_filter_v6(request: &CliRequest) -> RouteV6Filter {
    let filter: RouteV6Filter = if let Some(protocol) = &request.args.protocol {
        let origin = RouteOrigin::from(protocol);
        Box::new(move |(_, route): &(&Ipv6Prefix, &Route)| route.origin == origin)
    } else {
        Box::new(|(_, _)| true)
    };
    filter
}
fn show_vrf_routes(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = db.vrftable.read().map_err(|_| CliError::InternalError)?;

    if ipv4 {
        let filter = route_filter_v4(&request);
        if let Some(vrfid) = request.args.vrfid {
            show_ipv4_routes_single_vrf(request, &vrftable, vrfid, &filter)
        } else {
            show_ipv4_routes_multi(request, &vrftable, &filter)
        }
    } else {
        let filter = route_filter_v6(&request);
        if let Some(vrfid) = request.args.vrfid {
            show_ipv6_routes_single_vrf(request, &vrftable, vrfid, filter)
        } else {
            show_ipv6_routes_multi(request, &vrftable, &filter)
        }
    }
}

#[inline]
fn show_vrf_nexthops_single(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let out: String;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        if let Ok(vrf) = vrf.read() {
            if ipv4 {
                out = format!("{}", VrfV4Nexthops(&vrf));
            } else {
                out = format!("{}", VrfV6Nexthops(&vrf));
            }
        } else {
            return Err(CliError::InternalError);
        }
    } else {
        return Err(CliError::NotFound(format!("No VRF with id {vrfid} exists")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

#[inline]
fn show_vrf_nexthops_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        if let Ok(vrf) = vrf.read() {
            if ipv4 {
                out += format!("{}", VrfV4Nexthops(&vrf)).as_ref();
            } else {
                out += format!("{}", VrfV6Nexthops(&vrf)).as_ref();
            }
        }
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_vrf_nexthops(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = db.vrftable.read().map_err(|_| CliError::InternalError)?;

    if let Some(vrfid) = request.args.vrfid {
        show_vrf_nexthops_single(request, &vrftable, vrfid, ipv4)
    } else {
        show_vrf_nexthops_multi(request, &vrftable, ipv4)
    }
}

fn show_vrfs(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    if let Some(vni) = request.args.vni {
        if let Ok(vrftable) = db.vrftable.read() {
            if let Ok(vrf) = vrftable.get_vrf_by_vni(vni) {
                if let Ok(vrf) = vrf.read() {
                    Ok(CliResponse::from_request_ok(request, format!("\n{}", vrf)))
                } else {
                    Err(CliError::InternalError)
                }
            } else {
                Err(CliError::NotFound(format!("VRF with vni {vni}")))
            }
        } else {
            Err(CliError::InternalError)
        }
    } else {
        let vrftable = db.vrftable.read().map_err(|_| CliError::InternalError)?;
        Ok(CliResponse::from_request_ok(
            request,
            format!("\n{}", vrftable),
        ))
    }
}

fn _handle_cli_request(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let response = match request.action {
        CliAction::ShowRouterInterfaces => {
            let iftable = db.iftable.read().map_err(|_| CliError::InternalError)?;
            CliResponse::from_request_ok(request, format!("\n{}", iftable))
        }
        CliAction::ShowRouterInterfaceAddresses => {
            let iftable = db.iftable.read().map_err(|_| CliError::InternalError)?;
            let iftable_addrs = IfTableAddress(&iftable);
            CliResponse::from_request_ok(request, format!("\n{}", iftable_addrs))
        }
        CliAction::ShowRouterVrfs => return show_vrfs(request, db),
        CliAction::ShowRouterEvpnRmacStore => {
            let rmac_store = db.rmac_store.read().map_err(|_| CliError::InternalError)?;
            CliResponse::from_request_ok(request, format!("\n{}", rmac_store))
        }
        CliAction::ShowRouterEvpnVtep => {
            let vtep = db.vtep.read().map_err(|_| CliError::InternalError)?;
            CliResponse::from_request_ok(request, format!("{}", vtep))
        }
        CliAction::ShowAdjacencies => {
            let adjtable = db.atable.read().map_err(|_| CliError::InternalError)?;
            CliResponse::from_request_ok(request, format!("\n{}", adjtable))
        }
        CliAction::ShowRouterIpv4Routes => {
            return show_vrf_routes(request, db, true);
        }
        CliAction::ShowRouterIpv6Routes => {
            return show_vrf_routes(request, db, false);
        }
        CliAction::ShowRouterIpv4NextHops => {
            return show_vrf_nexthops(request, db, true);
        }
        CliAction::ShowRouterIpv6NextHops => {
            return show_vrf_nexthops(request, db, false);
        }
        //CliAction::ShowRouterIpv4FibEntries => {}
        //CliAction::ShowRouterIpv6FibEntries => {},
        _ => Err(CliError::NotSupported("Not implemented yet".to_owned()))?,
    };
    Ok(response)
}

pub fn handle_cli_request(
    sock: &UnixDatagram,
    peer: &SocketAddr,
    request: CliRequest,
    db: &RoutingDb,
) {
    trace!("Got cli request: {:#?} from {:?}", request, peer);

    let cliresponse = _handle_cli_request(request.clone(), db)
        .unwrap_or_else(|e| CliResponse::from_request_fail(request, e));

    let response = cliresponse.serialize().expect("Serialization");
    let response_len = (response.len() as u64).to_ne_bytes();
    let _ = sock.send_to_addr(&response_len, peer); // FIXME
    match sock.send_to_addr(&response, peer) {
        Ok(len) => trace!("Sent cli response ({len} octets)"),
        Err(e) => error!("Failure sending CLI response: {e}"),
    };
}
