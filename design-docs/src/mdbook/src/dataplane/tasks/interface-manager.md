# Interface manager

We need an agent to create linux network interfaces in response to configuration requests.

My vote would be to use [`rust-netlink`](https://github.com/rust-netlink/rtnetlink) as I am familiar with it and I (mostly) like it.
