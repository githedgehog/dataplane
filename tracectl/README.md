# Dynamic run-time tracing control

## Background, why this crate exists and what it does

- The dataplane implementation uses the _tracing_ crate to emit logs, in all of the crates that make it.
- The tasks carried out by those crates are diverse, happen concurrently and have different time requirements.
- Troubleshooting and testing is becoming hard for the usual reason: high log-levels can cause an overwhelming amount of
  (mostly useless) data; too low of a log-level may not capture enough data to understand a failure.
  In production, the performance penalty of verbose logging or their demanding storage requirements make it not feasible
  high log-levels other than for a subset of the logs and in small periods of time for troubleshooting.
- The tracing crate allows to dynamically change the log-level of logs/traces via the so-called _EnvFilter_.
- However, we currently (miss)use a single hard-coded EnvFilter, without exploiting its flexibility: pretty much all logs
  either disabled or governed by a single log-level set at compile time.

Ideally, we would be able to change traces' log levels (or even enable/disable them) selectively for the distinct
subsystems, at runtime.
Run-time adjustment of the log-level can be achieved by the EnvFilter object and its reloading capabilities.
The EnvFilter allows adjusting log-levels for each _target_.
Targets exist for _events_ and _spans_.
Think of targets as scopes where traces belong or are sent to: when some trace like `info!("Hey")` is added to the code,
target is implicitly created and automatically named, by default, based on the path of the module/submodule where the log
resides in the source code (this is done using the `module_path!()` built-in).
Knowing target identifiers is needed to adjust their log-level.
This can be problematic in the dataplane implementation since the code is spread across distinct crates: we'd like to
control the verbosity of targets across all crates in a **centralized** fashion; however, keeping some "target database"
not be easy because, if we use the implicit path-based identifiers, the targets in such a database may accidentally get
out-of-sync if crates get internally re-organized.
For instance, a trace emitted within some `sStateful` submodule within the `nat` crate may use an implicit target of
`nat::stateful`.
If the nat crate happened to be re-organized or some of the modules renamed, the target ids may become, say,
`cgnat::modes::stateful`.
This would require the database of targets to be updated and replace `nat::stateful` by `cgnat::modes::stateful`.
Some way to get stable identifiers for implicitly-named targets is needed.

One option would be to explicitly set the target names in all the member crates.
That would solve the issue of the database becoming out-of-sync on crate reorganization.
However, that would not solve the problem of populating the target database in the first place: any time a crate defined
new target, we'd still need to update the database to add it.
This may be solved by letting the participating crates register their targets in the database.
However, such as solution is inconvenient if done at run-time: how would crates declare their targets? Would there need
an initialization routine per crate? Who would call that?

This crate exists to solve the above issues allowing:

- the automatic registration of targets across multiple crates in a centralized database, _at build time_, ensuring that:
  - target names are _always_ up-to-date in the database
  - no target is missed
- programmatically changing of each of the target log levels at run-time

## Usage model and requirements

- This crate cannot (nor should) understand trace semantics.
  Trace/log semantics and their relations must be provided by the crates defining them.
- Crates _register_ their targets of interest (the targets whose log-level is to be dynamically adjusted) by _declaring_
  them, along with their initial, default log level, a stable _name_ and optional **tags**.
  Tags serve two purposes.
  First, they act as stable identifiers to refer to targets independently of their path; e.g.
  in an API.
  Second, a target may be associated with multiple tags.
  This allows controlling multiple targets simultaneously.

For instance, in a packet pipeline, each network function (NF) may emit logs to a distinct target; e.g.
a NAT NF may have a target labeled as _nat_.
This may allow enabling / disabling NAT-related debug logs at runtime, while only emitting warnings or errors in production.
If, in addition, the NAT (and rest of NFs) are associated with some tag _pipeline_, one may be able to enable / disable the
logs (or restrict them to, say, up to INFO) in all of the NFs composing the pipeline.
So, the takeaway is that tags represent **sets of targets** and a target can be member of an arbitrary number of sets.

- Tags are implemented as strings since each crate should be able to define them and having a custom type (e.g.
  some _enum_ in a centralized crate, like this one) would entail needing to update that crate every time some other crate
  required a new tag.
- However, if a tag is to be shared by distinct crates, the consistency of that needs to be enforced outside of this crate.

**Note:** The _name_ of a target is its main identifier and is automatically treated as a _tag_.
Therefore, registered targets always have at least one tag to control them.

## Implementation

This implementation has about 3 pieces:

- a _tracing controller_: a thread-safe database of targets, with some static initialization, that allows changing the
  log-level of targets and the default one and that allows reporting which targets are available, with which tags and
  log-level.
  This is important to be able to expose the targets in some form of API.
  We may expose the _tags_ as stable identifiers.
- the automated discovery of targets at link time so that no APIs are needed to declare targets and tags.
- macros to ease target declaration and simplify the addition of logs

## Usage

### Target configuration and registration (how to declare targets in crates)

#### Implicit targets

Targets are implicitly created by macros like `info!()`, with a path that defaults to `module_path!()`.
In order to be able to control the verbosity of those targets, these need to be _registered_.
Registering such implicit targets is straightforward.
We just need to declare the target in the module with macro `trace_target!` to associate it with a _name_, the initial
log-level and additional, optional tags.

```rust
// import trace_target! macro to register targets
use tracectl::trace_target;

// declare target within the current module with name mytarget1 and additional tag "some-other-tag"
trace_target!("mytarget1", LevelFilter::ERROR, &["some-other-tag"]);
```

**Note**: the _name_ of a target (`"mytarget1"` above) needs not be specified in the array of tags and will be
automatically added.

#### Custom targets

Placing a `trace_target!` stanza in each module/submodule should make all traces in a crate controllable via tag(s).
We may, however, need more control within a module/submodule and be able to govern log levels at a higher granularity.
This can be achieved by declaring _custom_ targets.
Registering a custom target --a target with an explicitly-set identifier-- can be done similarly as

```rust
custom_target!("my-custom-target", LevelFilter::ERROR, &["my-feature"]);
```

The above simply registers a configuration for a target called `"my-custom-target"`.
However that will do nothing if the target does not exist.
For such a target to exist, some logs (events/spans) should refer to it.
In order to emit logs within some custom target, the existing macros can be used, specifying the target as a key-value:

```rust
info!(target:"my-custom-target", "This is a log");
```

In order to make the above less verbose, this crate defines new macros (`terror, twarn, tinfo, tdebug` and `ttrace`)
which allow you to write, instead:

```rust
tinfo!("my-custom-target", "This is a log");
```

So, a consistent way of defining custom targets within a module may be:

```rust
const T1: &str = "my-target1";
const T2: &str = "my-target2";
custom_target!(T1, LevelFilter::ERROR, &["my-feature"]);
custom_target!(T2, LevelFilter::WARN, &["my-feature"]);

fn some_function(...) {
  if bug {
     terror!(T1, "Something bad happened!");
  }
}

impl FOO {
  fn method_1(...) {
    twarn!(T2, "Warning, this is bad but not too bad");
  }
}

impl BAR {
  fn method_1(...) {
    tdebug!(T2, "Blah, blah, blah");
    ttrace!(T2, "I am a parrot");
  }
}

```

With the above, each target gets a unique _name_ (equal to the target name) and a common tag.
So, every target is controlled by 2 tags: a dedicated one and `"my-feature"`.

With the initial target log-levels in the example, only the first two logs would be emitted.

#### Third-party crate targets

The dataplane uses third-party crates that emit logs themselves (e.g.
_tonic_ or _h2_), whose source code we don't want
to modify.
The solution to control their log-levels is to declare a _custom_ target configuration **elsewhere** as

```rust
custom_target!("tonic", LevelFilter::ERROR, &["third-party"])
```

... where `"tonic"` may be used to control all logs in the crate and `"third-party"` be a shared tag to control all
third-party crates.
Additional custom targets could be created for the crate's modules, but that would require knowing the internal
organization of the crate and such configs could get out of sync.
Using a single target config with the name of the crate should guarantee that the configuration is in sync, which suffices
in our case since we may use those target configs to mute all logs or limit them to just errors.

### Notes

- Using custom targets has implications on log formatting, depending on how the formatting layer is configured, since
  target names may be displayed.
- Targets may be declared _without_ tags: they will always get one equal to their _name_.
- The way the target registration works, targets may be declared in any place in the code; even within functions.
  The recommendation is, however, to place them at the beginning of each source code file.
- The way the Envfilters are built by this crate, if an (implicit) target is not registered (i.e. no `trace_target!()`
  is explicitly set) in some module/submodule, its log-level will be that of the nearest ancestor in the hierarchy.
  If no ancestor target is explicitly registered, the log-level will be governed by the _default_.
  This means that `trace_target!()` _needs not be added in every source code file_.
  The rule of thumb should be: if you believe that some set of debug logs are worth being governed separately (e.g.
  because they are generally verbose and usually not needed, but may be worth enabling at run-time), then declare their target.
  Else, don't.
- Multiple registrations are possible but discouraged: one may overwrite the other.
  This crate issues a warning if a target is registered more than once.

### Run-time use (binary)

#### Initialization

At run-time, target log-levels are governed by a target "controller", which contains the target database.
Such a controller is initialized by

```rust
TracingControl::init();
```

In reality, the above is sugar-syntax to explicitly signal the initialization of a static controller object that gets
initialized as soon as function `get_trace_ctl()` is called.
That function is the one used to access the controller and call its methods.

```rust
let tctl = get_trace_ctl();
```

The type returned by the above function is `&'static TracingControl`, but this is of no importance in practice.

#### Controlling target log-levels

Target log levels may be adjusted with method `set_tag_level()` indicating a tag and the desired log-level.
For instance, to set the log-level for tag "NAT" to Warning (so that only errors and warnings are emitted), one would
write:

```rust
get_trace_ctl().set_tag_level("NAT", LevelFilter::WARN);
```

Notice that this method expects a `LevelFilter` struct instead of a variant of the `Level` enum.
`LevelFilter` is a transparent wrapper to `Option<Level>` defined in the _tracing-core_ crate that maps
`LevelFilter::OFF` to `None`.
So, the method uses `LevelFilter` instead of `Level` so that logs can be disabled with `LevelFilter::OFF` (instead of
`None`), avoiding the need to write `Some(Level::XX)` for any other case.

#### Controlling the default log-level

Logs emitted to targets that have not been registered will be governed by the _default_ log-level.
The tracing controller also allows setting the desired default log-level as:

```rust
get_trace_ctl().set_default_level(LevelFilter::ERROR);
```

#### Checking targets, tags and levels

The tracing controller has several other methods to:

- retrieve the log-level for a given target, given its name
- retrieve the config for a given target, given its name
- retrieve the list of tags
- retrieve the current default log-level
- retrieve the target configs for a given tag.

The first two methods may not seem too useful (other than for custom targets) since implicit target names may be unstable.
However, they are added to be able to look up the config for third-party targets.
Also, one may always be able to discover the real (unstable) target names
by retrieving the set of targets having a given tag, provided that targets are given at least one tag.
Therefore, the recommendation is to _define at least one dedicated tag for each target, be it implicit or custom_.
