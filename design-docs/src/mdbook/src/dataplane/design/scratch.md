# Scratch

## Performance considerations

### Configuration information updates

Optimizing for configuration rate update at this point is absurd.
Pay it no mind.

Even poor _write_ performance is fine in the short term.
Read performance is slightly more concerning, be even that is a relatively modest issue.

Configuration data is neither large nor frequently updated.

We should instead focus on other properties:

1. _strong_ durability,
2. _strict_ referential integrity,
3. immediate consistency,
4. transactional updates,
5. partition tolerance.

Ideally, we would also get

1. reversible operation log,
2. rewind capability,
3. integration with the rest of the telemetry stack.

### Route information updates

Optimize for _thousands_ of sustained route updates per second.
Not millions.
There is no point in optimizing for route table thrashing.
Any network will behave poorly under those conditions (all of which reflect incorrect control plane behavior).

The only times when route update performance is expected to be the controlling factor are:

1. system startup,
2. major changes to peers.

Both of which are transient and well suited to batch-oriented updates.

Still, it is also important to consider the fact that even modest updates to the routing table can cause updates to the connection tracking tables as well.

### Connection tracking information updates

Connection tracking information updates _very_ quickly.
We can expect a sustained rate of hundreds of thousands of updates per second.
The rate at which connections can be offloaded (and the latency of installing and removing those offloads) is certain to be governing property in system performance overall.

The faster the offload is installed, the more quickly the processing of that flow becomes the network card's problem.
And the network card is very efficient.
Hardware offloading makes a huge difference, so we need to focus on rapidly installing offloads.

## Transactionality

[left-right] is lit.

[left-right]: https://github.com/jonhoo/left-right

## Packet walk

```plantuml
@startuml
hide empty fields
hide empty attributes
hide empty members
hide stereotype
hide circle

!$s = 0
!$ss = 0

!function $step()
!return "(" + $s + ")"
!endfunction

!procedure $step_next()
!$ss = 1
!$s = $s + 1
!endprocedure

!procedure $sstep_next()
!$ss = $ss + 1
!endprocedure

!function $sstep()
!return "(" + $s + "." + $ss + ")"
!endfunction

!$sty = {
  "added": "<color:#green>",
  "updated": "<color:#blue>"
}

!$end = "</color>"

class RouteTable {
  routes4: Lpm<Ipv4Addr, Ipv4Addr>,
}

class NeighborTable {
  fdb: HashMap<Ipv4Addr, Mac>,
}

class ConnectionTableIngress as "ConnectionTable<Ingress>" {
  map: HashMap<(L3, L4), (L3, L4)>
}

class ConnectionTableEgress as "ConnectionTable<Egress>" {
  map: HashMap<(L3, L4), (L3, L4)>
}

class IngressFrame as "$step() ingress frame" {
  **Layer 1**
  $sty.added**ingress interface: u32**$end
  ---
  **Layer 2:**
  eth.src: Mac
  eth.dst: Mac
  eth.proto: u16 <assume ipv4>
  ---
  **Layer 3:**
  ip.ttl: u8
  ip.proto: u8 <assume tcp>
  ip.src: Ipv4Addr
  ip.dst: Ipv4Addr
  ---
  **Layer 4:**
  tcp.src: u16
  tcp.dst: u16
}

$sstep_next()

IngressFrame <-- ConnectionTableIngress: $sstep() lookup

$sstep_next()

IngressFrame -> IngressNatFrame: "$sstep() becomes"

$step_next()

class IngressNatFrame as "$step() Ingress NATed Frame" {
  **Layer 1:**
  ingress interface: u32
  ---
  **Layer 2:**
  eth.src: Mac
  eth.dst: Mac
  eth.proto: u16 <assume ipv4>
  ---
  **Layer 3:**
  ip.ttl: u8
  ip.proto: u8 <assume tcp>
  ip.src: Ipv4Addr
  $sty.updated**ip.dst: Ipv4Addr**$end
  ---
  **Layer 4:**
  tcp.src: u16
  $sty.updated**tcp.dst: u16**$end
}

IngressNatFrame <-- RouteTable: "$sstep() lookup"
$sstep_next()
'NeighborTable --> IngressNatFrame: "$sstep() lookup"
IngressNatFrame <-- NeighborTable: "$sstep() lookup"
$sstep_next()
IngressNatFrame -> RoutedFrame: "$sstep() becomes"

$step_next()

class RoutedFrame as "$step() Routed Frame" {
  **Layer 1:**
  $sty.updated**egress interface: u32**$end
  ---
  **Layer 2:**
  $sty.updated**eth.src: Mac**$end
  $sty.updated**eth.dst: Mac**$end
  eth.proto: u16 <assume ipv4>
  ---
  **Layer 3:**
  $sty.updated**ip.ttl: `prior - 1`**$end
  ip.proto: u8 <assume tcp>
  ip.src: Ipv4Addr
  ip.dst: Ipv4Addr
  ---
  **Layer 4:**
  tcp.src: u16
  tcp.dst: u16
}

RoutedFrame <-- ConnectionTableEgress: $sstep() lookup
$sstep_next()
RoutedFrame -> EgressNatFrame: $sstep() becomes

$step_next()

class EgressNatFrame as "$step() Egress NATed Frame" {
  **Layer 1:**
  egress interface: u32
  ---
  **Layer 2:**
  eth.src: Mac
  eth.dst: Mac
  eth.proto: u16 <assume ipv4>
  ---
  **Layer 3:**
  ip.ttl: `prior - 1`
  ip.proto: u8 <assume tcp>
  $sty.updated**ip.src: Ipv4Addr**$end
  ip.dst: Ipv4Addr
  ---
  **Layer 4:**
  $sty.updated**tcp.src: u16**$end
  tcp.dst: u16
}

@enduml
```

```plantuml
@startuml
!pragma teoz true

!$sty_per_host = %lighten(yellow, 80)
!$sty_per_core = %lighten(blue, 80)
!$sty_per_vpc = %lighten(orange, 80)
!$sty_per_vpc_per_core = %lighten(palegreen, 10)


box per host $sty_per_host
  participant ASIC
end box
box per core $sty_per_core
  participant RxQueue
end box

box per VPC dispatched to core $sty_per_vpc_per_core
  participant Vpc.IngressQueue as "VpcIngressQueue"
  participant Vpc.Worker as "VpcWorker"
end box

box per VPC $sty_per_vpc
  participant ConnectionTable.Ingress as "ConnectionTable\n<Ingress>"
  participant RoutingTable as "RoutingTable"
  participant NeighborTable as "NeighborTable"
  participant ConnectionTable.Egress as "ConnectionTable\n<Egress>"
end box

box per VPC dispatched to core $sty_per_vpc_per_core
  participant Vpc.EgressQueue as "VpcEgressQueue"
end box

box per core $sty_per_core
  participant TxQueue
end box

box per host $sty_per_host
  participant ASIC_egress as "ASIC"
end box


ASIC -> RxQueue : ingress
& RxQueue -> Vpc.IngressQueue : burst
& Vpc.IngressQueue -> Vpc.Worker : drain

Vpc.Worker -> ConnectionTable.Ingress : lookup
return match

Vpc.Worker -> RoutingTable : lookup
return match

Vpc.Worker -> NeighborTable : lookup
return match

Vpc.Worker -> ConnectionTable.Egress : lookup
return match

Vpc.Worker -> Vpc.EgressQueue : push

& Vpc.EgressQueue -> TxQueue : pull
& TxQueue -> ASIC_egress : burst


@enduml
```


```plantuml
@startuml
!pragma teoz true
hide empty description

state a {
  state a.frozen
  state a.mutable
}

state b {
  state b.frozen
  state b.mutable
}

a.frozen -> a.mutable : atomic
a.mutable -> a.frozen : swap

a.frozen --> b.frozen : ref
a.mutable --> b.mutable : ref



@enduml
```

```plantuml
@startuml
!pragma teoz true
!$sty = {
	"question": "#gold",
	"action": "#lightblue",
	"future": "#lightgreen",
	"attention": "#pink",
	"critical_path": "#orange"
}
!$action = $sty.action
!$question = $sty.question
!$future = $sty.future
!$attention = $sty.attention
group ingress (hardware)
  :Frame arrives at ASIC;
  $sty.action:Classify (lookup VPC and ingress interface);
  if (match(VPC, ingress interface)) then (yes)
      $sty.action:set meta;
      $sty.action:decap / pop tags;
      $sty.action:push to RxQueue;
  else
      end
  end if
end group

group software
  $sty.action:poll RxQueue;
  $sty.action:read frame metadata;
  note right
    This still needs to be verified
    although confidence is high.
  end note
  switch (match (ingress interface))
    case (hit)
      $sty.critical_path:lookup VPC/VRF from
      ingress interface;
      note right $sty.attention
        VPC miss should be
        **provably** impossible
        here.
      end note
      $sty.critical_path:ingress NAT
      (if any);
      switch (NAT lookup)
        case (new)
          :compute new mapping;
          :compute new offload;
          :enqueue new offload;
        case (established|related)
          :do nat;
        case (invalid)
          end
      endswitch
      
      $sty.critical_path:routing;
      :lookup nexthop (IP, egress interface);
      :lookup nexthop MAC;
      :rewrite src and dst mac;
      :dec ttl;
      if (ttl) then (0)
        end
      else (>0)
      end if
      
      $sty.critical_path:egress NAT
      (if any);
      
      switch (NAT lookup)
        case (new)
          :compute new mapping;
          :compute new offload;
          :enqueue new offload;
        case (established|related)
          :do nat;
        case (invalid)
          end
      endswitch
      
    case (miss)
      $sty.future:warn if count > some threshold;
      end
  endswitch
@enduml
```

```puml
@startuml

rectangle agent {
 rectangle agent_to_manager_channel as "manager channel"
}


rectangle worker {
  rectangle poller {
    rectangle rx_queue as "rx queue"
    rectangle tx_queue as "tx queue"
    rectangle offload_queue as "offload queue"
  }
  rectangle rx_buffer as "rx buffer"
  rectangle tx_buffer as "tx buffer"
}

rectangle manager {
  collections worker_channel as "worker channel"
  collections manager_to_agent_channel as "agent channel"
}

rx_queue --> rx_buffer : burst
tx_queue <-- tx_buffer : burst

agent_to_manager_channel <--> manager_to_agent_channel





@enduml
```
