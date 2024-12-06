# Management Plane - Dataplane Interaction

We need to settle on how the management plane and dataplane interact. 

1. We need a transport protocol (eg., tcp session, http session with [SSE](https://en.wikipedia.org/wiki/Server-sent_events), [WebSocket](https://en.wikipedia.org/wiki/WebSocket)).
2. We need a protocol (schema for the data we transport)
3. We need an overall strategy (kill-and-fill or differential updates)


