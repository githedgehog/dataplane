# Sync with other gateway(s)

We need to

1. pick a transport
2. pick a protocol

As for transport, we can likely start with TCP (although RoCE is almost objectively more appropriate for this job).

As for protocol, we can likely use either [`bitcode`](https://crates.io/crates/bitcode/) or [`bincode`](https://docs.rs/bincode/latest/bincode/).

I expect this will be a task we do later on in the project, but before we reach 1.0.

This is a particularly tricky subject as it needs to be accounted for at all planning stages but should not be implemented until later in the process. 
The sooner we implement this function the more complex all the inevitable surrounding refactoring will be.


```yaml
label:
  - milestone
  - sync
```
