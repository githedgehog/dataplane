// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: prefix list

use crate::frr::renderer::builder::{ConfigBuilder, Render};
use crate::models::internal::routing::prefixlist::*;
use std::fmt::Display;

/* Impl Display */
impl Display for PrefixListMatchLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrefixListMatchLen::Ge(len) => write!(f, "ge {len}"),
            PrefixListMatchLen::Le(len) => write!(f, "le {len}"),
        }
    }
}
impl Display for PrefixListPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrefixListPrefix::Any => write!(f, "any"),
            PrefixListPrefix::Prefix(prefix) => write!(f, "{prefix}"),
        }
    }
}
impl Display for PrefixListAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrefixListAction::Deny => write!(f, "deny"),
            PrefixListAction::Permit => write!(f, "permit"),
        }
    }
}

/* Impl Render */
impl Render for PrefixListEntry {
    type Context = String;
    type Output = String;
    fn render(&self, ctx: &Self::Context) -> String {
        let mut out = format!("{} seq {} {} {}", ctx, self.seq, self.action, self.prefix);
        if let Some(len_match) = &self.len_match {
            out += format!(" {}", &len_match).as_str();
        }
        out
    }
}
impl Render for PrefixList {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut config = ConfigBuilder::new();
        let pfx = format!("ip prefix-list {}", self.name);
        if let Some(description) = &self.description {
            config += format!("{pfx} description \"{description}\"");
        }
        self.entries.iter().for_each(|e| config += e.render(&pfx));
        config
    }
}
impl Render for PrefixListTable {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        self.values().for_each(|plist| cfg += plist.render(&()));
        cfg
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use routing::prefix::Prefix;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_ip_prefix_list_render() {
        let mut plist = PrefixList::new(
            "underlay-from-spines",
            Some("Some custom prefix list for a vpc".to_owned()),
        );
        plist.add_entry(PrefixListEntry::new(
            1,
            PrefixListAction::Permit,
            PrefixListPrefix::Any,
            Some(PrefixListMatchLen::Le(31)),
        ));

        plist.add_entry(PrefixListEntry::new(
            2,
            PrefixListAction::Deny,
            PrefixListPrefix::Prefix(Prefix::from((IpAddr::from_str("8.8.8.8").unwrap(), 32))),
            None,
        ));

        plist.add_entry(PrefixListEntry::new(
            3,
            PrefixListAction::Permit,
            PrefixListPrefix::Prefix(Prefix::from((
                IpAddr::from_str("192.168.90.0").unwrap(),
                24,
            ))),
            None,
        ));

        let out = plist.render(&());
        println!("{out}");
    }
}
