# Required features for MVP

At a very high level, these are the _user facing_ features that we require to reach MVP with the gateway:

1. BGP underlay
2. EVPN overlay
3. VPC routing (aka RIOT)
4. VPC nat 44/66
5. VPC nat 64
6. Telemetry
7. Rate limiting
8. AB fault tolerance
9. Management API

## User-facing features

<figure title="User-facing feature dependencies">

```plantuml
@startdot
digraph features {
labelloc=t
graph [ranksep=0.6]

node[shape="rect"]
BGP_underlay [ label="BGP underlay", style=filled, color="lightblue"]
EVPN_overlay [ label="EVPN overlay", style=filled, color="lightblue"]
VPC_routing [ label="VPC routing", style=filled, color="lightblue"]
VPC_nat44_66 [ label="VPC nat44/66", style=filled, color="lightblue"]
VPC_nat64 [ label="VPC nat64", style=filled, color="lightblue"]
Telemetry [ label="Telemetry/observability", style=filled, color="lightblue"]
rate_limiting [ label="Rate limiting", style=filled, color="lightblue"]
Fault_tolerance [ label="Fault tolerance", style=filled, color="lightblue"]
Management_API [label="Management API", style=filled, color="lightblue"]
all [label="*"]
all -> Management_API
Management_API -> all

BGP_underlay -> EVPN_overlay;
EVPN_overlay -> VPC_routing;
VPC_routing -> VPC_nat44_66;
VPC_routing -> VPC_nat64;
VPC_routing -> rate_limiting;
EVPN_overlay -> Fault_tolerance;
Fault_tolerance -> VPC_nat64;
Fault_tolerance -> VPC_nat44_66;
VPC_routing -> Telemetry;
VPC_nat44_66 -> Telemetry [xlabel="weak"];
VPC_nat64 -> Telemetry [xlabel="weak"];
rate_limiting -> Telemetry [xlabel="weak"];
}
@enddot
```

> A graph of the functional dependencies between the required _user facing_ features.
> Each node on the graph represents a feature.
> No feature can be _completed_ without all of the other features which point to it.

</figure>

<figure title="Major feature dependencies (internal)">

```plantuml
@startdot
digraph features {
  labelloc=t
  node [shape="box"]
  graph [ranksep=0.8]
  label=< <b>Feature map<br/>(major features)</b> >

  BGP_underlay [ label="BGP underlay", style=filled, color="lightblue" ]
  EVPN_overlay [ label="EVPN overlay", style=filled, color="lightblue" ]
  VPC_routing [ label="VPC routing\n(aka RIOT)", style=filled, color="lightblue" ]
  VPC_nat44_66 [ label="VPC nat44/66", style=filled, color="lightblue" ]
  VPC_nat64 [ label="VPC nat64", style=filled, color="lightblue" ]
  telemetry [ label="Telemetry/observability", style=filled, color="lightblue" ]
  rate_limiting [ label="Rate limiting", style=filled, color="lightblue" ]
  fault_tolerance [ label="Fault tolerance", style=filled, color="lightblue" ]
  Management_API [ label="Management API", style=filled, color="lightblue" ]

  control_plane_integration [ label="control plane integration"]
  state_sync [ label="state sync" ]
  hardware_offloaded_nat [ label="offload nat" ]
  hardware_offloaded_routing [ label="Underlay route offload" ]
  hardware_offloaded_vpc [ label="VPC route offload" ]
  hardware_offloading_basic [ label="basic offloading" ]
  datastore_integration [ label="datastore integration" ]
  
  all [label="*"]
  Management_API -> all
  all -> Management_API

  datastore_integration -> control_plane_integration
  datastore_integration -> hardware_offloaded_routing
  hardware_offloading_basic -> hardware_offloaded_routing
  hardware_offloaded_routing -> BGP_underlay
  fault_tolerance -> VPC_nat44_66
  fault_tolerance -> VPC_nat64
  BGP_underlay -> EVPN_overlay
  EVPN_overlay -> VPC_routing
  EVPN_overlay -> state_sync
  EVPN_overlay -> hardware_offloaded_vpc
  hardware_offloaded_nat -> VPC_nat44_66
  hardware_offloaded_nat -> VPC_nat64
  VPC_nat44_66 -> telemetry [xlabel="weak"]
  VPC_nat64 -> telemetry [xlabel="weak"]
  VPC_routing -> telemetry
  VPC_routing -> VPC_nat44_66
  VPC_routing -> VPC_nat64
  VPC_routing -> rate_limiting
  control_plane_integration -> BGP_underlay
  state_sync -> fault_tolerance
  hardware_offloaded_vpc -> hardware_offloaded_nat
  hardware_offloaded_vpc -> rate_limiting
  hardware_offloading_basic -> hardware_offloaded_vpc
  rate_limiting -> telemetry [xlabel="weak"]
}
@enddot
```

> Here is a _very_ high-level graph of the functional dependencies between the required features.
> Each node on the graph represents a feature.
> No feature can be _completed_ without all the other features which point to it.
> Features shown in blue are user facing.
> All other features represent internal implementation concerns.

</figure>
