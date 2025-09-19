// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tracing runtime control.

#![allow(unused)]

use std::fmt::Display;
use std::sync::{Arc, Mutex, Once};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use crate::trace_target;
use crate::{display::TargetCfgDbByTag, targets::TRACING_TARGETS};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{
    EnvFilter, Registry,
    filter::{LevelFilter, targets},
    prelude::*,
    reload,
};

trace_target!(LevelFilter::INFO, &["tracectl"]);

#[derive(Debug, Clone)]
pub struct TargetCfg {
    pub(crate) target: &'static str,
    pub(crate) level: LevelFilter,
    pub(crate) tags: &'static [&'static str],
}
impl TargetCfg {
    pub const fn new(
        target: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
    ) -> Self {
        Self {
            target,
            level,
            tags,
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
    pub(crate) level: LevelFilter,
    pub(crate) targets: HashMap<&'static str, TargetCfg>,
    pub(crate) tags: HashMap<&'static str, Tag>,
}

impl TargetCfgDb {
    fn new(level: LevelFilter) -> Self {
        let mut db = Self {
            level,
            targets: HashMap::new(),
            tags: HashMap::new(),
        };
        // load link-time-learnt targets
        for target in TRACING_TARGETS {
            db.register(target.target, target.level, target.tags);
        }
        db
    }
    fn register(
        &mut self,
        target: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
    ) {
        debug!("Registering target {target} level={level} tags={tags:?}");
        let tconfig = TargetCfg::new(target, level, tags);
        if let Some(exist) = self.targets.insert(target, tconfig) {
            warn!("Target {} has been multiply defined!", exist.target);
        }
        for tag in tags {
            if let Some(tag) = self.tags.get_mut(tag) {
                tag.targets.insert(target);
            } else {
                self.tags.insert(tag, Tag::new(tag, target));
            }
        }
    }

    fn env_filter(&self) -> EnvFilter {
        let mut f = EnvFilter::new(self.level.to_string());
        for unit in self.targets.values() {
            let directive = format!("{}={}", unit.target, unit.level);
            f = f.add_directive(directive.parse().unwrap());
        }
        f
    }
}

#[derive(Debug)]
pub struct TracingControl {
    db: Arc<Mutex<TargetCfgDb>>,
    reload_filter: Arc<reload::Handle<EnvFilter, Registry>>,
}
impl TracingControl {
    fn new() -> Self {
        let mut db = TargetCfgDb::new(LevelFilter::INFO);
        let (filter, reload_filter) = reload::Layer::new(db.env_filter());

        // formatting layer
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_line_number(true)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(true)
            .with_level(true);

        use tracing_subscriber::fmt::Layer;
        use tracing_subscriber::layer::Layered;

        let (fmt_layer, reload_fmt) = reload::Layer::new(fmt_layer);

        // we should not be initializing the subscriber here, but that's fine atm
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()
            .expect("Failed to initialize tracing subscriber");

        Self {
            db: Arc::new(Mutex::new(db)),
            reload_filter: Arc::new(reload_filter),
            //reload_fmt: Arc::new(reload_fmt),
        }
    }
    fn reload(&self, filter: EnvFilter) {
        self.reload_filter.reload(filter);
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
    pub fn set_tag_level(&self, tag: &str, level: LevelFilter) {
        //must go first to avoid deadlock
        let targets = self.get_targets_by_tag(tag);

        let mut db = self.db.lock().unwrap();
        let mut changed = false;
        for target in targets {
            if let Some(t) = db.targets.get_mut(target) {
                if t.level != level {
                    t.level = level;
                    changed = true;
                }
            } else {
                error!("No target '{target}' exists. This is a bug");
            }
        }
        if changed {
            info!("Set log level for tag '{tag}' to {level}");
            self.reload(db.env_filter());
        }
    }
    pub fn set_default_level(&self, level: LevelFilter) {
        if let Ok(mut db) = self.db.lock()
            && db.level != level
        {
            db.level = level;
            info!("Set default log level to {level}");
            self.reload(db.env_filter());
        }
    }
    pub fn get_default_level(&self) -> LevelFilter {
        let db = self.db.lock().unwrap();
        db.level
    }
    pub fn register(&self, path: &'static str, level: LevelFilter, tags: &'static [&'static str]) {
        if let Ok(mut db) = self.db.lock() {
            db.register(path, level, tags);
            self.reload(db.env_filter());
        }
    }
    pub fn get_tags(&self) -> impl Iterator<Item = Tag> {
        self.db.lock().unwrap().tags.clone().into_values()
    }
    pub fn get_target(&self, target: &str) -> Option<TargetCfg> {
        self.db.lock().unwrap().targets.get(target).cloned()
    }
    pub fn get_target_all(&self) -> impl Iterator<Item = TargetCfg> {
        self.db.lock().unwrap().targets.clone().into_values()
    }
    pub fn get_targets_by_tag(&self, tag: &str) -> impl Iterator<Item = &'static str> {
        let db = self.db.lock().unwrap();
        let targets: Vec<_> = if let Some(tag) = db.tags.get(tag) {
            tag.targets.iter().cloned().collect()
        } else {
            vec![]
        };
        targets.into_iter()
    }
    pub fn dump_targets_by_tag(&self) {
        let db = self.db.lock().unwrap();
        let sorted = TargetCfgDbByTag(&db);
        info!("{sorted}");
    }
    pub fn dump(&self) {
        let db = self.db.lock().unwrap();
        info!("{db}");
    }
}

#[cfg(test)]
mod tests {
    use crate::control::{Tag, TargetCfg, TracingControl, get_trace_ctl};
    use tracing::Level;
    use tracing::level_filters::LevelFilter;
    use tracing::{debug, error, event, info, trace, warn};

    const TARGET_1: &str = "my-target-1";
    const TARGET_2: &str = "my-target-2";
    const TARGET_3: &str = "my-target-3";

    fn log_target1() {
        println!("logging from target {TARGET_1}");
        error!(target: TARGET_1, "This is an ERROR log");
        warn!(target: TARGET_1,  "This is a WARN log");
        info!(target: TARGET_1,  "This is an INFO log");
        debug!(target: TARGET_1, "This is a DEBUG log");
        trace!(target: TARGET_1, "This is a TRACE log");
    }
    fn log_target2() {
        println!("logging from target {TARGET_2}");
        error!(target: TARGET_2, "This is an ERROR log");
        warn!(target: TARGET_2,  "This is a WARN log");
        info!(target: TARGET_2,  "This is an INFO log");
        debug!(target: TARGET_2, "This is a DEBUG log");
        trace!(target: TARGET_2, "This is a TRACE log");
    }
    fn log_target3() {
        println!("logging from target {TARGET_3}");
        error!(target: TARGET_3, "This is an ERROR log");
        warn!(target: TARGET_3,  "This is a WARN log");
        info!(target: TARGET_3,  "This is an INFO log");
        debug!(target: TARGET_3, "This is a DEBUG log");
        trace!(target: TARGET_3, "This is a TRACE log");
    }

    #[test]
    fn test_init() {
        TracingControl::init();
        let tctl = get_trace_ctl();
        info!(
            "The current default loglevel is {}",
            tctl.get_default_level()
        );
    }

    #[test]
    fn test_target_levels() {
        println!();
        let tctl = get_trace_ctl();
        tctl.register(TARGET_1, LevelFilter::TRACE, &[TARGET_1]);
        tctl.register(TARGET_2, LevelFilter::DEBUG, &[TARGET_2]);
        tctl.register(TARGET_3, LevelFilter::INFO, &[TARGET_3]);
        println!("{}", tctl.db.lock().unwrap());

        log_target1();
        log_target2();
        log_target3();

        tctl.set_tag_level(TARGET_1, LevelFilter::OFF);
        tctl.set_tag_level(TARGET_2, LevelFilter::WARN);
        tctl.set_tag_level(TARGET_3, LevelFilter::ERROR);

        log_target1();
        log_target2();
        log_target3();
    }

    #[test]
    fn test_silent() {
        println!();
        let tctl = get_trace_ctl();
        tctl.set_default_level(LevelFilter::OFF);

        log_target1();
        log_target2();
        log_target3();

        tctl.register(TARGET_1, LevelFilter::ERROR, &[TARGET_1]);
        tctl.register(TARGET_2, LevelFilter::ERROR, &[TARGET_2]);
        tctl.register(TARGET_3, LevelFilter::ERROR, &[TARGET_3]);

        log_target1();
        log_target2();
        log_target3();
    }

    use crate::targets::TRACING_TARGETS;
    use crate::trace_target;

    fn some_function1() {
        trace_target!("func1", LevelFilter::ERROR, &["function1"]);
    }
    fn some_function2() {
        // this won't be registered since the module is already registered
        trace_target!(LevelFilter::OFF, &["function2"]);
    }

    #[test]
    fn test_auto_register_macro() {
        // declare implicitly-named target
        trace_target!(LevelFilter::ERROR, &["macro-auto"]);

        // declare custom targets
        trace_target!("target-1", LevelFilter::ERROR, &["target-1"]);
        trace_target!("target-2", LevelFilter::WARN, &["target-2", "macro-custom"]);
        trace_target!("target-3", LevelFilter::OFF, &["macro-custom"]);

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
        trace_target!("target-4", LevelFilter::OFF, &["target-4"]);

        let tags: Vec<Tag> = tctl.get_tags().collect();
        println!("{tags:#?}");
        println!("{}", tctl.db.lock().unwrap());
    }

    #[test]
    fn test_targeted_macro() {
        // this test is just to check builds
        use crate::tinfo;
        const TARGET: &str = "MY-TARGET";
        trace_target!(TARGET, LevelFilter::TRACE, &["targeted-macro"]);
        let tctl = get_trace_ctl();

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
        trace_target!(TARGET, LevelFilter::TRACE, &[TARGET]);

        let tctl = get_trace_ctl();
        assert!(tctl.db.lock().unwrap().targets.contains_key(TARGET));
        let target = tctl.get_target(TARGET).expect("Should be found");
        assert_eq!(target.level, LevelFilter::TRACE);

        tctl.set_tag_level(TARGET, LevelFilter::WARN);
        let updated = tctl.get_target(TARGET).expect("Should be found");
        assert_eq!(updated.level, LevelFilter::WARN);

        let mut targets = tctl.get_targets_by_tag(TARGET);
        assert_eq!(targets.next().unwrap(), TARGET);
    }
}
