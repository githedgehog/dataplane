// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tracing runtime control.

#![allow(unused)]

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::sync::{Arc, Mutex, Once};

use crate::targets::TRACING_TARGETS;
use crate::trace_target;
use tracing::{info, debug, warn};
use tracing_subscriber::{EnvFilter, Registry, filter::LevelFilter, prelude::*, reload};

trace_target!(LevelFilter::INFO, &["tracectl"]);

#[derive(Debug)]
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

#[derive(Debug)]
pub(crate) struct TargetCfgDb {
    pub(crate) level: LevelFilter,
    pub(crate) targets: HashMap<&'static str, TargetCfg>,
}

impl TargetCfgDb {
    fn new(level: LevelFilter) -> Self {
        Self {
            level,
            targets: HashMap::new(),
        }
    }
    fn register(
        &mut self,
        target: &'static str,
        level: LevelFilter,
        tags: &'static [&'static str],
    ) {
        debug!("Registering target {target} level={level} tags={tags:?}");
        let unit = TargetCfg::new(target, level, tags);
        if let Some(exist) = self.targets.insert(target, unit) {
            warn!("Target {} has been multiply defined!", exist.target);
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
    reload_handle: Arc<reload::Handle<EnvFilter, Registry>>,
}
impl TracingControl {
    fn new() -> Self {
        let mut db = TargetCfgDb::new(LevelFilter::INFO);
        for t in TRACING_TARGETS {
            db.register(t.target, t.level, t.tags);
        }

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_line_number(true)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(true)
            .with_level(true);

        let (filter, reload_handle) = reload::Layer::new(db.env_filter());

        let subscriber = Registry::default().with(filter).with(fmt_layer);
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

        info!("Initialized tracing control. Log level is {}", db.level);
        Self {
            db: Arc::new(Mutex::new(db)),
            reload_handle: Arc::new(reload_handle),
        }
    }
    fn reload(&self, filter: EnvFilter) {
        self.reload_handle.reload(filter);
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
        let mut changed = false;
        let mut db = self.db.lock().unwrap();
        for unit in db.targets.values_mut() {
            if unit.tags.contains(&tag) && unit.level != level {
                changed = true;
                unit.level = level;
            }
        }
        if changed {
            info!("Set log level for {tag} to {level}");
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
    pub fn get_tags(&self) -> impl Iterator<Item = &'static str> {
        let mut map = HashSet::new();
        for target in TRACING_TARGETS {
            target.tags.iter().for_each(|tag| {
                map.insert(*tag);
            });
        }
        map.into_iter()
    }
    pub fn dump(&self) {
        let db = self.db.lock().unwrap();
        info!("{db}");
    }
}

#[cfg(test)]
mod tests {
    use crate::control::{TargetCfg, TracingControl, get_trace_ctl};
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
        info!("The current loglevel is {}", tctl.get_default_level());
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
        // declare automatically-named target declaration
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

        let tags: Vec<&'static str> = tctl.get_tags().collect();
        println!("{tags:#?}");
        println!("{}", tctl.db.lock().unwrap());
    }

    #[test]
    fn test_targeted_macro() {
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
}
