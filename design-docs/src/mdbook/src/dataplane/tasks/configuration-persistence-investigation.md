# Configuration persistence

We need to officially pick a data store for configuration information.

This data store _is not_ intended for storing "fast" state.
Rather, this store needs to hold configuration data which is

1. durable
2. atomic
3. strongly typed
4. immediately consistent

## etcd

[etcd] is a reasonable choice because

1. It is already in use in kubernetes and is therefore likely to be well-maintained and tested.
2. we are already using / integrating with kubernetes so any flaws in `etcd` are likely to impact us anyway.

I have used [`zookeeper`](https://zookeeper.apache.org/) in the past and *strongly recommend against it*.

I would also consider [`consul`](https://github.com/hashicorp/consul) but [the license](https://github.com/hashicorp/consul/blob/main/LICENSE) is *_not_* acceptable.

A newer entry in the space is [`nacos`](https://github.com/alibaba/nacos) but I think it is less well suited since it only seems to support eventual consistency.

## rqlite

_I have not used [`rqlite`],_ but it seems to be a reasonable (if young) option.
My biggest concern is that [transactions](https://rqlite.io/docs/api/api/#transactions) support seems _very_ weak.

- has a supported [rust client](https://github.com/tomvoet/rqlite-rs) (and even a [sqlx](https://github.com/launchbadge/sqlx) client in the form of [sqlx-rqlite](https://crates.io/crates/sqlx-rqlite))
- [weak](https://rqlite.io/docs/api/read-consistency/#weak), [linearizable](https://rqlite.io/docs/api/read-consistency/#linearizable), and [strong](https://rqlite.io/docs/api/read-consistency/#strong) consistency models supported
- [transactions](https://rqlite.io/docs/api/api/#transactions) (this seems less than ideal tho)

## TiKV

[TiKV] seems like the **strongest near-term option** on the list.

I think that the biggest advantage is in the case that we want to _eventually_ switch to [TiDB].
That strategy allows us the most flexibility to use a "real" database in the future while using a "simple" KV database in the near term.

## TiDB

[TiDB] is a [MySQL] compatible [distributed SQL] database built on top of [TiKV].

The thing which I find most striking about this database is the excellent documentation and robust feature set (robust all things considered).

- [Generated columns](https://docs.pingcap.com/tidb/dev/generated-columns)
- [JSON](https://docs.pingcap.com/tidb/dev/data-type-json)
- [Referential integrity](https://docs.pingcap.com/tidb/dev/foreign-key)
- [Transactions](https://docs.pingcap.com/tidb/dev/transaction-overview)
- [Views](https://docs.pingcap.com/tidb/dev/views)
- [Change data capture](https://docs.pingcap.com/tidb/stable/ticdc-overview)

## Summary

Thus, I think the real choice is between [`etcd`], [TiDB], and [TiKV].

That choice comes down to how much we value the functionality of sql (multiple indexes, referential integrity, strong schema) vs. the upsides of kv databases (watches, more easily evolved schema).

{{#include ../../links.md}}
