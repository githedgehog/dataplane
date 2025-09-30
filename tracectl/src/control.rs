// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tracing runtime control.

use ordermap::OrderMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Once};
use thiserror::Error;
#[allow(unused)]
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, Registry, filter::LevelFilter, prelude::*, reload};

use crate::display::TargetCfgDbByTag;
use crate::targets::{TRACING_TAG_ALL, TRACING_TARGETS};
use crate::trace_target;
trace_target!("tracectl", LevelFilter::INFO, &[]);

#[derive(Debug, Error, PartialEq)]
pub enum TraceCtlError {
    #[error("Reload tracing failure")]
    ReloadFailure,
    #[error("Unknown tag {0}")]
    UnknownTag(String),
}

#[derive(Debug, Clone)]
pub struct TargetCfg {
    pub(crate) target: &'static str,
    pub(crate) name: &'static str,
    pub(crate) level: LevelFilter,
    pub(crate) tags: Vec<&'static str>,
    pub(crate) custom: bool,
}
impl TargetCfg {
    fn new(
        target: &'static str,
        name: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
        custom: bool,
    ) -> Self {
        // add name as tag if it is not there
        let mut tags = tags.to_vec();
        if !tags.contains(&name) {
            tags.push(name);
        }
        // always add tag "all" (except to target "all")
        if name != TRACING_TAG_ALL {
            tags.push(TRACING_TAG_ALL);
        }
        Self {
            target,
            name,
            level,
            tags,
            custom,
        }
    }
}
#[derive(Debug, Clone)]
pub struct Tag {
    pub(crate) tag: &'static str,
    pub(crate) targets: HashSet<&'static str>,
}
impl Tag {
    fn new(tag: &'static str, target: &'static str) -> Self {
        let mut targets = HashSet::with_capacity(1);
        targets.insert(target);
        Self { tag, targets }
    }
}

#[derive(Debug)]
pub(crate) struct TargetCfgDb {
    pub(crate) default: LevelFilter,
    pub(crate) targets: OrderMap<&'static str, TargetCfg>,
    pub(crate) tags: OrderMap<&'static str, Tag>,
}

impl TargetCfgDb {
    fn new(level: LevelFilter) -> Self {
        let mut db = Self {
            default: level,
            targets: OrderMap::new(),
            tags: OrderMap::new(),
        };
        // load link-time-learnt targets
        for target in TRACING_TARGETS {
            db.register(
                target.target,
                target.name,
                target.level,
                target.tags,
                target.custom,
            );
        }
        db
    }
    fn register(
        &mut self,
        target: &'static str,
        name: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
        custom: bool,
    ) {
        let tconfig = TargetCfg::new(target, name, level, tags, custom);
        let tags = tconfig.tags.clone();

        if let Some(exist) = self.targets.insert(target, tconfig) {
            warn!("Target {} has been multiply defined!", exist.target);
        }
        for tag in &tags {
            if let Some(tag) = self.tags.get_mut(tag) {
                tag.targets.insert(target);
            } else {
                self.tags.insert(tag, Tag::new(tag, target));
            }
        }
    }
    fn env_filter(&self) -> EnvFilter {
        let mut f = EnvFilter::new(self.default.to_string());
        for target in self.targets.values() {
            let directive = format!("{}={}", target.target, target.level);
            f = f.add_directive(directive.parse().unwrap());
        }
        f
    }
    /// Generate a config as a string that would provide the current tracing configurations.
    /// Note: multiple distinct configs may provide the same configuration, given that a target
    /// may be configured by distinct tags. The following is the simplest implementation that
    /// does not attempt to group targets by common tags.
    pub fn as_config_string(&self) -> String {
        let mut out = String::new();
        out += format!("default={}", self.default).as_str();
        for target in self.targets.values() {
            out += format!(",{}={}", target.name, target.level).as_str();
        }
        out
    }
    #[allow(unused)]
    pub fn tag_targets_mut(&mut self, tag: &str) -> impl Iterator<Item = &mut TargetCfg> {
        let targets: Vec<_> = if let Some(tag) = self.tags.get(tag) {
            self.targets
                .values_mut()
                .filter(|target| tag.targets.contains(target.target))
                .collect()
        } else {
            vec![]
        };
        targets.into_iter()
    }
    pub fn tag_targets(&self, tag: &str) -> impl Iterator<Item = &TargetCfg> {
        let targets: Vec<_> = if let Some(tag) = self.tags.get(tag) {
            self.targets
                .values()
                .filter(|target| tag.targets.contains(target.target))
                .collect()
        } else {
            vec![]
        };
        targets.into_iter()
    }
    pub fn set_tag_level(&mut self, tag: &str, level: LevelFilter) -> Result<u32, TraceCtlError> {
        let tag = self
            .tags
            .get(tag)
            .ok_or_else(|| TraceCtlError::UnknownTag(tag.to_owned()))?;

        let mut changed: u32 = 0;
        for target in self
            .targets
            .values_mut()
            .filter(|target| tag.targets.contains(target.target))
        {
            if target.level != level {
                target.level = level;
                changed += 1;
            }
        }
        Ok(changed)
    }
    fn check_tags(&self, tags: &[&str]) -> Result<(), TraceCtlError> {
        for tag in tags.iter() {
            if !self.tags.contains_key(tag) {
                return Err(TraceCtlError::UnknownTag(tag.to_string()));
            }
        }
        Ok(())
    }
    pub fn reconfigure<'a>(
        &mut self,
        default: Option<LevelFilter>,
        tag_config: impl Iterator<Item = (&'a str, LevelFilter)>,
    ) -> Result<u32, TraceCtlError> {
        let mut changed: u32 = 0;
        let mut map: OrderMap<&'static str, LevelFilter> = OrderMap::new();
        for (tag, level) in tag_config {
            let Some(tag) = self.tags.get(tag) else {
                return Err(TraceCtlError::UnknownTag(tag.to_string()));
            };
            for target in &tag.targets {
                let e = map.entry(target).or_insert(level);
                if *e < level {
                    *e = level;
                }
            }
        }
        for (target, level) in map.iter() {
            let target = self
                .targets
                .get_mut(target)
                .unwrap_or_else(|| unreachable!());
            if target.level != *level {
                target.level = *level;
                changed += 1;
            }
        }
        if let Some(level) = default {
            self.default = level;
        }
        Ok(changed)
    }
}

pub struct TracingControl {
    db: Arc<Mutex<TargetCfgDb>>,
    reload_filter: Arc<reload::Handle<EnvFilter, Registry>>,
}
impl TracingControl {
    fn new() -> Self {
        let db = TargetCfgDb::new(LevelFilter::INFO);
        let (filter, reload_filter) = reload::Layer::new(db.env_filter());

        // formatting layer
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_line_number(true)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(true)
            .with_level(true);

        // we should not be initializing the subscriber here, but that's fine atm
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()
            .expect("Failed to initialize tracing subscriber");

        Self {
            db: Arc::new(Mutex::new(db)),
            reload_filter: Arc::new(reload_filter),
        }
    }
    fn reload(&self, filter: EnvFilter) {
        if let Err(e) = self.reload_filter.reload(filter) {
            error!("Failed to reload tracing filter: {e}");
        }
    }
    #[cfg(test)]
    fn register(
        &self,
        target: &'static str,
        name: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
        custom: bool,
    ) {
        if let Ok(mut db) = self.db.lock() {
            db.register(target, name, level, tags, custom);
            self.reload(db.env_filter());
        }
    }
}

/// Get a reference to a static [`TracingControl`], initializing it if needed
static INIT: Once = Once::new();
static mut TRACING_CTL: Option<TracingControl> = None;
pub fn get_trace_ctl() -> &'static TracingControl {
    INIT.call_once(|| unsafe {
        TRACING_CTL = Some(TracingControl::new());
    });
    #[allow(static_mut_refs)]
    unsafe {
        TRACING_CTL.as_ref().unwrap()
    }
}

// public methods for TracingControl
impl TracingControl {
    pub fn init() {
        get_trace_ctl();
    }
    pub fn set_tag_level(&self, tag: &str, level: LevelFilter) -> Result<(), TraceCtlError> {
        let mut db = self.db.lock().unwrap();
        let changed = db.set_tag_level(tag, level)?;
        if changed > 0 {
            self.reload(db.env_filter());
        }
        info!("Changed log level for tag '{tag}' to {level}. Targets changed: {changed}");
        Ok(())
    }
    pub fn set_default_level(&self, level: LevelFilter) {
        if let Ok(mut db) = self.db.lock()
            && db.default != level
        {
            info!("Changing default log-level from {} to {level}", db.default);
            db.default = level;
            self.reload(db.env_filter());
        }
    }
    pub fn get_default_level(&self) -> LevelFilter {
        self.db.lock().unwrap().default
    }

    /// Parse a string made of comma-separated tag=level; level = [off,error,warn,info,debug,trace]
    fn parse_tracing_config(input: &str) -> Result<OrderMap<String, LevelFilter>, String> {
        let mut result = OrderMap::new();

        for item in input.split(',') {
            let item = item.trim();
            if let Some((tag, level)) = item.split_once('=') {
                let level = LevelFilter::from_str(level.trim())
                    .map_err(|e| format!("invalid level {}: {}", level.trim(), e))?;
                result.insert(tag.trim().to_string(), level);
            } else {
                return Err("Invalid syntax: it should be tag=loglevel".to_string());
            }
        }
        Ok(result)
    }
    pub fn setup_from_string(&self, input: &str) -> Result<(), String> {
        let config = Self::parse_tracing_config(input)?;

        // if input has default=level, set the default
        if let Some(level) = config.get("default") {
            self.set_default_level(*level);
        }

        // This is meant to be called from the cmd line. Unlike in reconfigure(),
        // we take into account ordering here
        for (tag, level) in config.iter().filter(|(tag, _)| *tag != "default") {
            self.set_tag_level(tag, *level).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// All of the following are to lookup the database or log it
    pub fn get_tags(&self) -> impl Iterator<Item = Tag> {
        self.db.lock().unwrap().tags.clone().into_values()
    }
    pub fn get_tag(&self, tag: &str) -> Option<Tag> {
        self.db.lock().unwrap().tags.get(tag).cloned()
    }
    pub fn get_target(&self, target: &str) -> Option<TargetCfg> {
        self.db.lock().unwrap().targets.get(target).cloned()
    }
    pub fn get_target_all(&self) -> impl Iterator<Item = TargetCfg> {
        self.db.lock().unwrap().targets.clone().into_values()
    }
    pub fn get_targets_by_tag(&self, tag: &str) -> impl Iterator<Item = TargetCfg> {
        let db = self.db.lock().unwrap();
        db.tag_targets(tag)
            .map(|x| (*x).clone())
            .collect::<Vec<_>>()
            .into_iter()
    }
    pub fn as_config_string(&self) -> String {
        self.db.lock().unwrap().as_config_string()
    }
    pub fn reconfigure<'a>(
        &self,
        default: Option<LevelFilter>,
        tag_config: impl Iterator<Item = (&'a str, LevelFilter)>,
    ) -> Result<(), TraceCtlError> {
        let mut db = self.db.lock().unwrap();
        db.reconfigure(default, tag_config)?;
        self.reload_filter
            .reload(db.env_filter())
            .map_err(|_| TraceCtlError::ReloadFailure)?;
        Ok(())
    }
    pub fn check_tags(&self, tags: &[&str]) -> Result<(), TraceCtlError> {
        self.db.lock().unwrap().check_tags(tags)
    }
    pub fn as_string(&self) -> String {
        let db = self.db.lock().unwrap();
        db.to_string()
    }
    pub fn as_string_by_tag(&self) -> String {
        let db = self.db.lock().unwrap();
        TargetCfgDbByTag(&db).to_string()
    }
    #[cfg(test)]
    pub fn dump_targets_by_tag(&self) {
        let db = self.db.lock().unwrap();
        let sorted = TargetCfgDbByTag(&db);
        info!("{sorted}");
    }
    #[cfg(test)]
    pub fn dump(&self) {
        let db = self.db.lock().unwrap();
        info!("{db}");
    }
}

#[cfg(test)]
mod tests {
    use crate::control::{Tag, TracingControl, get_trace_ctl};
    use crate::targets::TRACING_TARGETS;
    use crate::{LevelFilter, custom_target, trace_target};
    use tracing::Level;
    use tracing::event_enabled;
    #[allow(unused)]
    use tracing::{debug, error, info, trace, warn};

    const TARGET_1: &str = "my-target-1";
    const TARGET_2: &str = "my-target-2";
    const TARGET_3: &str = "my-target-3";

    #[test]
    fn test_init() {
        TracingControl::init();
        let tctl = get_trace_ctl();
        info!(
            "The current default loglevel is {}",
            tctl.get_default_level()
        );
        println!("{:#?}", tctl.db.lock().unwrap());
    }

    #[test]
    fn test_target_levels() {
        println!();
        let tctl = get_trace_ctl();
        tctl.register(TARGET_1, TARGET_1, LevelFilter::TRACE, &[], true);
        tctl.register(TARGET_2, TARGET_2, LevelFilter::DEBUG, &[], true);
        tctl.register(TARGET_3, TARGET_3, LevelFilter::INFO, &[], true);
        tctl.dump();
        tctl.dump_targets_by_tag();

        // target 1 : TRACE
        assert!(event_enabled!(target: TARGET_1, Level::ERROR));
        assert!(event_enabled!(target: TARGET_1, Level::WARN));
        assert!(event_enabled!(target: TARGET_1, Level::INFO));
        assert!(event_enabled!(target: TARGET_1, Level::DEBUG));
        assert!(event_enabled!(target: TARGET_1, Level::TRACE));

        // target 2 : DEBUG
        assert!(event_enabled!(target: TARGET_2, Level::ERROR));
        assert!(event_enabled!(target: TARGET_2, Level::WARN));
        assert!(event_enabled!(target: TARGET_2, Level::INFO));
        assert!(event_enabled!(target: TARGET_2, Level::DEBUG));
        assert!(!event_enabled!(target: TARGET_2, Level::TRACE));

        // target 3 : INFO
        assert!(event_enabled!(target: TARGET_3, Level::ERROR));
        assert!(event_enabled!(target: TARGET_3, Level::WARN));
        assert!(event_enabled!(target: TARGET_3, Level::INFO));
        assert!(!event_enabled!(target: TARGET_3, Level::DEBUG));
        assert!(!event_enabled!(target: TARGET_3, Level::TRACE));

        println!(" ====== Changing log-levels ===== ");

        tctl.set_tag_level(TARGET_1, LevelFilter::OFF).unwrap();
        tctl.set_tag_level(TARGET_2, LevelFilter::WARN).unwrap();
        tctl.set_tag_level(TARGET_3, LevelFilter::ERROR).unwrap();

        // target 1 : OFF
        assert!(!event_enabled!(target: TARGET_1, Level::ERROR));
        assert!(!event_enabled!(target: TARGET_1, Level::WARN));
        assert!(!event_enabled!(target: TARGET_1, Level::INFO));
        assert!(!event_enabled!(target: TARGET_1, Level::DEBUG));
        assert!(!event_enabled!(target: TARGET_1, Level::TRACE));

        // target 2 : WARN
        assert!(event_enabled!(target: TARGET_2, Level::ERROR));
        assert!(event_enabled!(target: TARGET_2, Level::WARN));
        assert!(!event_enabled!(target: TARGET_2, Level::INFO));
        assert!(!event_enabled!(target: TARGET_2, Level::DEBUG));
        assert!(!event_enabled!(target: TARGET_2, Level::TRACE));

        // target 3 : ERROR
        assert!(event_enabled!(target: TARGET_3, Level::ERROR));
        assert!(!event_enabled!(target: TARGET_3, Level::WARN));
        assert!(!event_enabled!(target: TARGET_3, Level::INFO));
        assert!(!event_enabled!(target: TARGET_3, Level::DEBUG));
        assert!(!event_enabled!(target: TARGET_3, Level::TRACE));

        tctl.dump();
    }

    #[allow(unused)]
    fn some_function1() {
        custom_target!("func1", LevelFilter::ERROR, &["function1"]);
    }
    #[allow(unused)]
    fn some_function2() {
        // this won't be registered since the module is already registered
        // we don't panic but issue a warning at the moment
        trace_target!("foo", LevelFilter::OFF, &["function2"]);
    }

    #[test]
    fn test_auto_register_macro() {
        // declare implicitly-named target
        trace_target!("macro-auto", LevelFilter::ERROR, &[]);

        // declare custom targets
        custom_target!("target-1", LevelFilter::ERROR, &[]);
        custom_target!("target-2", LevelFilter::WARN, &[]);
        custom_target!("target-3", LevelFilter::OFF, &[]);

        // Target presence in static shared slice, even for targets declared later
        // This is linkme collecting them all at build/link time
        let static_targets: Vec<&str> = TRACING_TARGETS.iter().map(|c| c.target).collect();
        assert!(static_targets.contains(&module_path!()));
        assert!(static_targets.contains(&"target-1"));
        assert!(static_targets.contains(&"target-2"));
        assert!(static_targets.contains(&"target-3"));
        assert!(static_targets.contains(&"target-4")); // defined later
        assert!(static_targets.contains(&"func1")); // defined in a separate function

        // check target presence in database: all should be there even if defined later
        let tctl = get_trace_ctl();
        assert!(tctl.db.lock().unwrap().targets.contains_key(module_path!()));
        assert!(tctl.db.lock().unwrap().targets.contains_key("target-1"));
        assert!(tctl.db.lock().unwrap().targets.contains_key("target-2"));
        assert!(tctl.db.lock().unwrap().targets.contains_key("target-3"));
        assert!(tctl.db.lock().unwrap().targets.contains_key("target-4"));
        assert!(tctl.db.lock().unwrap().targets.contains_key("func1"));

        // this is declared after the checks
        custom_target!("target-4", LevelFilter::OFF, &["target-4"]);

        let tags: Vec<Tag> = tctl.get_tags().collect();
        println!("{tags:#?}");
        tctl.dump();
        tctl.dump_targets_by_tag();
    }

    #[test]
    fn test_targeted_macro() {
        // this test is just to check builds
        use crate::tinfo;
        const TARGET: &str = "MY-TARGET";
        custom_target!(TARGET, LevelFilter::TRACE, &[]);
        let _tctl = get_trace_ctl();

        tinfo!(
            TARGET,
            "An info log to target {TARGET} with param1={} param2={}",
            "hello",
            54
        );
    }

    #[test]
    fn test_change_target_level() {
        const TARGET: &str = "change-target-level";
        custom_target!(TARGET, LevelFilter::TRACE, &[]);

        let tctl = get_trace_ctl();
        assert!(tctl.db.lock().unwrap().targets.contains_key(TARGET));
        let target = tctl.get_target(TARGET).expect("Should be found");
        assert_eq!(target.level, LevelFilter::TRACE);

        tctl.set_tag_level(TARGET, LevelFilter::WARN).unwrap();
        let updated = tctl.get_target(TARGET).expect("Should be found");
        assert_eq!(updated.level, LevelFilter::WARN);

        let mut targets = tctl.get_targets_by_tag(TARGET);
        assert_eq!(targets.next().unwrap().target, TARGET);
    }

    #[test]
    fn test_change_tag_level() {
        let tctl = get_trace_ctl();

        const TAG: &str = "common-tag";
        const T1: &str = "t1";
        const T2: &str = "t2";
        const T3: &str = "t3";
        const T4: &str = "t4";

        custom_target!(T1, LevelFilter::DEBUG, &[TAG]);
        custom_target!(T2, LevelFilter::ERROR, &[TAG]);
        custom_target!(T3, LevelFilter::WARN, &[TAG]);
        custom_target!(T4, LevelFilter::INFO, &[TAG]);

        assert!(tctl.get_tag(TAG).is_some());
        let targets: Vec<_> = tctl.get_targets_by_tag(TAG).map(|t| t.target).collect();
        assert!(targets.contains(&T1));
        assert!(targets.contains(&T2));
        assert!(targets.contains(&T3));
        assert!(targets.contains(&T4));

        assert_eq!(tctl.get_target(T1).unwrap().level, LevelFilter::DEBUG);
        assert_eq!(tctl.get_target(T2).unwrap().level, LevelFilter::ERROR);
        assert_eq!(tctl.get_target(T3).unwrap().level, LevelFilter::WARN);
        assert_eq!(tctl.get_target(T4).unwrap().level, LevelFilter::INFO);

        tctl.set_tag_level(TAG, LevelFilter::OFF).unwrap();

        assert_eq!(tctl.get_target(T1).unwrap().level, LevelFilter::OFF);
        assert_eq!(tctl.get_target(T2).unwrap().level, LevelFilter::OFF);
        assert_eq!(tctl.get_target(T3).unwrap().level, LevelFilter::OFF);
        assert_eq!(tctl.get_target(T4).unwrap().level, LevelFilter::OFF);
    }

    #[test]
    fn test_setup_from_string() {
        const COMMON: &str = "common-tag-2";
        const T11: &str = "t11";
        const T22: &str = "t22";
        const T33: &str = "t33";
        const T44: &str = "t44";
        custom_target!(T11, LevelFilter::DEBUG, &[COMMON]);
        custom_target!(T22, LevelFilter::ERROR, &[COMMON]);
        custom_target!(T33, LevelFilter::WARN, &[COMMON]);
        custom_target!(T44, LevelFilter::INFO, &[COMMON]);

        let tctl = get_trace_ctl();
        tctl.set_tag_level(COMMON, LevelFilter::INFO).unwrap();
        tctl.set_tag_level("MY-TARGET", LevelFilter::INFO).unwrap();
        tctl.set_tag_level("target-4", LevelFilter::INFO).unwrap();
        tctl.dump_targets_by_tag();

        // update tracing configuration from string
        tctl.setup_from_string("common-tag-2=off,MY-TARGET=warn, target-4=error")
            .unwrap();

        // check if database has been updated
        tctl.dump_targets_by_tag();
        tctl.get_targets_by_tag(COMMON)
            .for_each(|t| assert_eq!(t.level, LevelFilter::OFF));
        tctl.get_targets_by_tag("MY-TARGET")
            .for_each(|t| assert_eq!(t.level, LevelFilter::WARN));
        tctl.get_targets_by_tag("target-4")
            .for_each(|t| assert_eq!(t.level, LevelFilter::ERROR));

        // were the changes enforced?
        assert!(!event_enabled!(target: T11, Level::ERROR));
        assert!(event_enabled!(target: "MY-TARGET", Level::WARN));
        assert!(!event_enabled!(target: "MY-TARGET", Level::DEBUG));
        assert!(event_enabled!(target: "target-4", Level::ERROR));
        assert!(!event_enabled!(target: "target-4", Level::WARN));

        // fail if level is bad
        assert!(tctl.setup_from_string("common-tag-2=bad").is_err());

        // fail if no level is given
        assert!(tctl.setup_from_string("common-tag-2=error, foo").is_err());

        // fail if tag is not known
        assert!(tctl.setup_from_string("unknown-tag=error").is_err());
    }

    #[test]
    fn test_overlapping_tags() {
        const T1: &str = "tag1";
        const T2: &str = "tag2";
        const X1: &str = "x1";
        const X2: &str = "x2";
        const X3: &str = "x3";
        const X4: &str = "x4";
        custom_target!(X1, LevelFilter::OFF, &[T1, T2]);
        custom_target!(X2, LevelFilter::OFF, &[T1]);
        custom_target!(X3, LevelFilter::OFF, &[T2]);
        custom_target!(X4, LevelFilter::OFF, &[T2, T1]);

        let tctl = get_trace_ctl();
        tctl.reconfigure(None, [(T1, LevelFilter::ERROR)].into_iter())
            .unwrap();
        tctl.get_targets_by_tag(T1)
            .for_each(|t| assert_eq!(t.level, LevelFilter::ERROR));

        tctl.reconfigure(
            None,
            [(T1, LevelFilter::OFF), (T2, LevelFilter::DEBUG)].into_iter(),
        )
        .unwrap();
        assert!(event_enabled!(target: X1, Level::DEBUG));
        assert!(!event_enabled!(target: X2, Level::ERROR));
        assert!(event_enabled!(target: X3, Level::DEBUG));
        assert!(event_enabled!(target: X4, Level::DEBUG));

        tctl.reconfigure(
            None,
            [
                (T1, LevelFilter::WARN),
                (T2, LevelFilter::ERROR),
                (X4, LevelFilter::DEBUG),
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(event_enabled!(target: X1, Level::WARN));
        assert!(event_enabled!(target: X2, Level::WARN));
        assert!(!event_enabled!(target: X2, Level::INFO));
        assert!(event_enabled!(target: X3, Level::ERROR));
        assert!(!event_enabled!(target: X3, Level::WARN));
        assert!(event_enabled!(target: X4, Level::DEBUG));
    }
}
