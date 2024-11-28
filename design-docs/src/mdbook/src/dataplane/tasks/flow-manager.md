# Flow manager

We will need

1. A method of creating, tracking, and editing flow tables
   1. This goal falls neatly under the life-cycle methods of rust.
   2. I don't think transactional edits to flow tables will be practical
2. Telemetry / error reporting on the flow tables
   1. Telemetry will need to be implemented by polling.  I don't think triggers are workable.
   2. Error reporting relates this issue closely to both the [control plane interface](./control-plane-interface.md) and the [routing manager](./route-manager.md).
      The essential point is that we _do not advertise routes which we cannot support_.
      For example, if we fail to offload a route, then it should not be advertised by BGP.
3. Mirroring 
   1. this is not especially difficult in terms of rte flow but needs to be accounted for in the timeline
4. QoS (TODO: make this another issue entirely)
   1. Traffic prioritization:
      1. Management-plane
      2. observability
      3. Control-plane
      4. GW - Synchronization
      5. User/tenant traffic

      The reasoning for the traffic prioritization is that you can block tenant traffic rather than the operational traffic and the system will keep working.  If the tenant traffic wins then DoS attacks or config mistakes can more easily drop the system.
   2. Rate limiting
      
      This is likely to be a major client requirement, so I think we should shoot for this as part of our 1.0 api.
   3. Full HH QoS model

      This just needs research.  I don't know the details of this.
