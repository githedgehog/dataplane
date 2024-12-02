# Pick a data store

We need to officially pick a data store for configuration information.

This data store _is not_ intended for storing "fast" state.
Rather, this store needs to hold configuration data which is

1. durable
2. atomic
3. strongly typed
4. immediately consistent

[`etcd`] is a reasonable choice because

1. It is already in use in kubernetes and is therefore likely to be well-maintained and tested.
2. we are already using / integrating with kubernetes so any flaws in `etcd` are likely to impact us anyway.

I have used [`zookeeper`](https://zookeeper.apache.org/) in the past and *strongly recommend against it*.

I would also consider [`consul`](https://github.com/hashicorp/consul) but [the license](https://github.com/hashicorp/consul/blob/main/LICENSE) is *_not_* acceptable.

A newer entry in the space is [`nacos`](https://github.com/alibaba/nacos) but I think it is less well suited since it only seems to support eventual consistency.

The remaining option I know of is [`rqlite`]. _I have not used it,_ but it seems to be a reasonable option.

- has a supported [rust client](https://github.com/tomvoet/rqlite-rs) (and even a [sqlx](https://github.com/launchbadge/sqlx) client in the form of [sqlx-rqlite](https://crates.io/crates/sqlx-rqlite))
- [weak](https://rqlite.io/docs/api/read-consistency/#weak), [linearizable](https://rqlite.io/docs/api/read-consistency/#linearizable), and [strong](https://rqlite.io/docs/api/read-consistency/#strong) consistency models supported
- [transactions](https://rqlite.io/docs/api/api/#transactions) (this seems less than ideal tho)

Thus, I think the real choice is between [`etcd`] and [`rqlite`].

That choice comes down to how much we value the functionality of sqlite (multiple indexes, referential integrity, strong schema) vs. the upsides of [etcd] (watches, battle tested, and more widely used).
