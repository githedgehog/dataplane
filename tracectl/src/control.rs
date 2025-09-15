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
