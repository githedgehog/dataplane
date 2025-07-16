// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: prefix list

use crate::frr::renderer::builder::{ConfigBuilder, Render, Rendered};
use config::internal::routing::prefixlist::*;

/* Impl Display */
impl Rendered for PrefixListMatchLen {
    fn rendered(&self) -> String {
        match self {
            PrefixListMatchLen::Ge(len) => format!("ge {len}"),
            PrefixListMatchLen::Le(len) => format!("le {len}"),
        }
    }
}
impl Rendered for PrefixListPrefix {
    fn rendered(&self) -> String {
        match self {
            PrefixListPrefix::Any => "any".to_string(),
            PrefixListPrefix::Prefix(prefix) => format!("{prefix}"),
        }
    }
}
impl Rendered for PrefixListAction {
    fn rendered(&self) -> String {
        match self {
            PrefixListAction::Deny => "deny".to_string(),
            PrefixListAction::Permit => "permit".to_string(),
        }
    }
}
impl Rendered for IpVer {
    fn rendered(&self) -> String {
        match self {
            IpVer::V4 => "ip".to_string(),
            IpVer::V6 => "ipv6".to_string(),
        }
    }
}

/* Impl Render */
impl Render for PrefixListEntry {
    type Context = (String, u32); /* u32 is sequence */
    type Output = String;
    fn render(&self, ctx: &Self::Context) -> String {
        let seq = ctx.1;
        let mut out = format!(
            "{} seq {} {} {}",
            ctx.0,
            seq,
            self.action.rendered(),
            self.prefix.rendered()
        );
        if let Some(len_match) = &self.len_match {
            out += format!(" {}", len_match.rendered()).as_str();
        }
        out
    }
}
impl Render for PrefixList {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut config = ConfigBuilder::new();
        let pfx = format!("{} prefix-list {}", self.ipver.rendered(), self.name);
        if let Some(description) = &self.description {
            config += format!("{pfx} description \"{description}\"");
        }
        self.entries
            .iter()
            .for_each(|(seq, e)| config += e.render(&(pfx.clone(), *seq)));
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
    use lpm::prefix::Prefix;

    #[test]
    fn test_ipv4_prefix_list_render() {
        let mut plist = PrefixList::new(
            "IPV4-prefix-list",
            IpVer::V4,
            Some("Some custom prefix list for a vpc".to_owned()),
        );
        plist
            .add_entry(
                Some(1),
                PrefixListEntry::new(
                    PrefixListAction::Permit,
                    PrefixListPrefix::Any,
                    Some(PrefixListMatchLen::Le(31)),
                ),
            )
            .expect("Should be ok");

        plist
            .add_entry(
                Some(2),
                PrefixListEntry::new(
                    PrefixListAction::Deny,
                    PrefixListPrefix::Prefix(Prefix::expect_from(("8.8.8.8", 32))),
                    None,
                ),
            )
            .expect("Should be ok");

        plist
            .add_entry(
                Some(3),
                PrefixListEntry::new(
                    PrefixListAction::Permit,
                    PrefixListPrefix::Prefix(Prefix::expect_from(("192.168.90.0", 24))),
                    None,
                ),
            )
            .expect("Should be ok");

        let out = plist.render(&());
        println!("{out}");
    }

    #[test]
    fn test_ipv6_prefix_list_render() {
        let mut plist = PrefixList::new(
            "IPV6-prefix-list",
            IpVer::V6,
            Some("Some custom prefix list for a vpc".to_owned()),
        );
        plist
            .add_entry(
                Some(1),
                PrefixListEntry::new(
                    PrefixListAction::Permit,
                    PrefixListPrefix::Any,
                    Some(PrefixListMatchLen::Le(31)),
                ),
            )
            .expect("Should be ok");

        plist
            .add_entry(
                Some(2),
                PrefixListEntry::new(
                    PrefixListAction::Deny,
                    PrefixListPrefix::Prefix(Prefix::expect_from(("3000:a:b::", 80))),
                    None,
                ),
            )
            .expect("Should be ok");
        let out = plist.render(&());
        println!("{out}");
    }

    #[test]
    #[should_panic]
    fn test_prefix_list_check_version() {
        let mut plist = PrefixList::new(
            "IPV6-prefix-list",
            IpVer::V6,
            Some("Some custom prefix list for a vpc".to_owned()),
        );
        plist
            .add_entry(
                None,
                PrefixListEntry::new(
                    PrefixListAction::Deny,
                    PrefixListPrefix::Prefix(Prefix::expect_from(("3000:a:b::", 80))),
                    None,
                ),
            )
            .expect("Should be ok");

        // this should panic because we attempt to add IPv4
        plist
            .add_entry(
                None,
                PrefixListEntry::new(
                    PrefixListAction::Permit,
                    PrefixListPrefix::Prefix(Prefix::expect_from(("192.168.90.0", 24))),
                    None,
                ),
            )
            .expect("Should be ok");
    }
}
