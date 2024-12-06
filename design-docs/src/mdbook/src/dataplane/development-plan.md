## Development plan

<figure title="Dependency graph (goal oriented)">

```plantuml
@startdot
!$ptr=./tasks
!$optional="color=lightyellow, style=filled"
!$started="color=lightblue, style=filled"
!$completed="color=lightgreen, style=filled"
!$urgent="color=orange, style=filled"
!$difficult="color=pink, style=filled"
digraph g {
  node [shape="box"]
  splines=ortho;
  
  graph [ranksep=0.9]
  labelloc=t
  overlap=false;
  concentrate="true";
  remincross=true;
  mclimit=800;
  compound=true;

  underlay_routing [label="underlay routing", href="$ptr/underlay-routing.html", fontcolor=blue]
  config_db_schema [label="config db schema", $difficult, href="$ptr/config-db-schema.html", fontcolor=blue]
  core_pinning [label="core pinning", $optional, href="$ptr/core-pinning.html", fontcolor=blue]
  cp_api_control_investigation [label=<<b>programmatic control of frr<br/>(investigation)</b>>, $urgent, href="$ptr/programmatic-control-of-frr.html", fontcolor=blue]
  cp_dev_env [label="control plane\ndev env", href="$ptr/control-plane-dev-env.html", fontcolor=blue]
  cp_image_creation [ label="Create control plane container image", href="$ptr/create-control-plane-image.html", fontcolor=blue]
  dp_dev_env [label="dataplane dev env", $completed, href="../../build/index.html", fontcolor=blue]
  dp_dp_state_sync [label="state sync\n(implementation)", $difficult, href="$ptr/state-sync.html", fontcolor=blue]
  dp_dp_state_sync_design [label="state sync\n(design)", $urgent, href="$ptr/state-sync-design.html", fontcolor=blue]
    dp_image_creation [label="dataplane image build", $completed]
  fault_tolerance [label="fault tolerance (implementation)", href="$ptr/fault-tolerance-implementation.html", fontcolor=blue]
  fault_tolerance_proof [label="fault tolerance (validation)", $difficult, href="$ptr/fault-tolerance-validation.html", fontcolor=blue]
    zebra_plugin_basic [ label="zebra plugin\n(basic)", href="$ptr/zebra-plugin.html", fontcolor=blue ]
  frr_programmatic_control [label=<<b>programmatic<br/>control of frr</b>>, $difficult, href="$ptr/programmatic-control-of-frr.html", fontcolor=blue]
    gw_test_env [label="gateway test env", href="$ptr/gateway-test-env.html", fontcolor=blue]
  investigate_config_persist [ label=<<b>configuration<br/>persistence<br/>(investigation)</b>>, $urgent, href="$ptr/configuration-persistence-investigation.html", fontcolor=blue ]
  local_traffic_ident [ label="identify local traffic", href="$ptr/identify-local-traffic.html", fontcolor=blue]
  mp_cp_interaction [ label="management plane \ncontrol plane interaction", href="$ptr/management-plane-control-plane-interaction.html", fontcolor=blue]
  mp_dp_interaction [ label="management plane \ndataplane interaction", href="$ptr/management-plane-dataplane-interaction.html", fontcolor=blue]
  nat64_investigation [label=<<b>NAT64 investigation</b>>, $urgent, href="$ptr/NAT64-investigation.html", fontcolor=blue]
    performance_measurement [ label="measure performance", href="$ptr/performance-measurement.html", fontcolor=blue]
  plugin_dp_proto [ label="plugin/dataplane protocol", $started, href="$ptr/dataplane-control-plane-protocol.html", fontcolor=blue]
  plugin_dp_transport [ label="plugin/dataplane transport", $completed, href="$ptr/dataplane-control-plane-transport.html", fontcolor=blue]
  public_internet_access [label="public internet access", href="$ptr/public-internet-access.html", fontcolor=blue]
  rate_limiting_investigation [label="rate limiting investigation", $completed]
  routing_manager [label="routing manager", href="$ptr/route-manager.html", fontcolor=blue]
  separate_cp_containers [ label="one cp daemon per container", $optional, href="$ptr/one-control-plane-daemon-per-container.html", fontcolor=blue]
    telemetry_basic [label="telemetry (basic)", href="$ptr/telemetry-basic.html", fontcolor=blue]
  telemetry_investigation [label="telemetry\n(investigation)", $completed, href="$ptr/telemetry-investigation.html", fontcolor=blue]
  telemetry_integrated [label="telemetry (integration)", href="$ptr/telemetry-integration.html", fontcolor=blue]
  vpc_nat44 [label="nat44", href="$ptr/NAT44.html", fontcolor=blue]
    vpc_nat64 [label="nat64", $difficult, href="$ptr/NAT64.html", fontcolor=blue]
  vpc_nat66 [label="nat66", href="$ptr/NAT66.html", fontcolor=blue]
    vpc_rate_limiting [label="vpc rate limiting", href="$ptr/vpc-rate-limiting.html", fontcolor=blue]
  vpc_routing [label="vpc routing", href="$ptr/vpc-routing.html", fontcolor=blue]
  vxlan_tunnels [label="vxlan tunnels", href="$ptr/vxlan-tunnels.html", fontcolor=blue]
  vxlan_tunnel_investigation [label="vxlan tunnels\n(investigation)", $completed]
  worker_lifecycle [label="dp worker lifecycle", href="$ptr/dataplane-worker-lifecycle.html", fontcolor=blue]

  nat64_investigation -> dp_dp_state_sync_design
  investigate_config_persist -> config_db_schema
  dp_dp_state_sync_design -> dp_dp_state_sync
  cp_api_control_investigation -> frr_programmatic_control
  frr_programmatic_control -> mp_cp_interaction
  vxlan_tunnel_investigation -> vxlan_tunnels
  vxlan_tunnels -> vpc_routing

  nat64_investigation -> vpc_nat64
  vpc_nat64 -> public_internet_access
  vpc_nat44 -> public_internet_access
  vpc_nat66 -> public_internet_access
  dp_dp_state_sync -> fault_tolerance

  rate_limiting_investigation -> vpc_rate_limiting
  telemetry_investigation -> telemetry_basic
  telemetry_basic -> telemetry_integrated

  mp_dp_interaction -> telemetry_integrated

  telemetry_integrated -> performance_measurement
  core_pinning -> performance_measurement
  dp_dp_state_sync -> performance_measurement

  vpc_routing -> vpc_rate_limiting
  mp_cp_interaction -> vpc_routing
  underlay_routing -> vpc_routing
  cp_dev_env -> gw_test_env
  cp_image_creation -> cp_dev_env
  cp_image_creation -> separate_cp_containers
  dp_dev_env -> gw_test_env
  dp_image_creation -> dp_dev_env
  gw_test_env -> zebra_plugin_basic
  zebra_plugin_basic -> routing_manager
  config_db_schema -> mp_cp_interaction
  config_db_schema -> mp_dp_interaction
  local_traffic_ident -> zebra_plugin_basic
  mp_dp_interaction -> vpc_routing
  plugin_dp_proto -> zebra_plugin_basic
  plugin_dp_transport -> zebra_plugin_basic
  routing_manager -> underlay_routing
  config_db_schema -> underlay_routing
  vpc_routing -> vpc_nat44
  vpc_routing -> vpc_nat64
  vpc_routing -> vpc_nat66
  worker_lifecycle -> core_pinning
  worker_lifecycle -> vpc_routing

  vpc_nat44 -> dp_dp_state_sync
  vpc_nat66 -> dp_dp_state_sync
  vpc_nat64 -> dp_dp_state_sync
  fault_tolerance -> fault_tolerance_proof
  
  subgraph cluster_legend {
    label="legend";
    started [label="started", $started]
    optional [label="optional", $optional]
    completed [label="\"completed\"", $completed]
    urgent [label="urgent", $urgent]
    difficult [label="difficult", $difficult]
  }

}
@enddot
```

<figcaption>

> Graph of the engineering development plan.
> Each node on the graph represents a task or required function.
> No task can be _completed_ without all the other tasks which point to it.
>
> * Tasks shown in orange are points of higher uncertainty and risk.
> * Tasks shown in pink are points of expected higher difficulty.
> * Tasks shown in gray are already completed.
</figcaption>
</figure>

> [!NOTE]
> I am recommending that tasks with higher uncertainty (shown in orange) be addressed with all possible speed.
> Especially if they directly connect to tasks of high expected difficulty.

> [!WARNING]
> Tasks of high expected difficulty are different from tasks which we expect will be very time-consuming.

{{#include ../links.md}}
