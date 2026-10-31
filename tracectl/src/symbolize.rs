// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Panic reports that can be symbolized after the fact.
//!
//! Shipped binaries are stripped of DWARF; it lives in the build's `debug` output, indexed by
//! build ID.  The backtrace color-eyre prints is resolved in-process, so it gets function names
//! from the symbol table but no file or line, and it prints no addresses to resolve later.
//!
//! This adds a section to each panic report with what is needed to resolve the trace offline:
//! every frame as an offset into the module it is in, and each module's build ID.

use findshlibs::{Avma, Segment, SharedLibrary, TargetSharedLibrary};
use std::collections::BTreeMap;
use std::fmt::Write;

/// Install color-eyre's hooks, with [`report`] appended to the panic report.
pub(crate) fn install() -> Result<(), color_eyre::Report> {
    let (panic_hook, eyre_hook) = color_eyre::config::HookBuilder::default().try_into_hooks()?;
    eyre_hook.install()?;
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("{}", panic_hook.panic_report(info));
        eprintln!("{}", report(&frames()));
    }));
    Ok(())
}

/// The return addresses on the current stack, innermost first.
fn frames() -> Vec<usize> {
    let mut ips = Vec::new();
    backtrace::trace(|frame| {
        ips.push(frame.ip() as usize);
        true
    });
    ips
}

/// A loaded object, as `llvm-symbolizer` needs to know it.
struct Module {
    name: String,
    build_id: Option<String>,
}

/// Where an address falls: which module, and at which address in that module's own (unrelocated)
/// address space.
struct Located {
    module: usize,
    svma: usize,
}

fn module_name(lib: &impl SharedLibrary) -> String {
    let path = lib.name().to_string_lossy();
    if path.is_empty() || path == "/proc/self/exe" {
        // glibc's loader reports the main program without a name; musl's static
        // `dl_iterate_phdr` reports it as `/proc/self/exe`.
        return std::env::current_exe()
            .ok()
            .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "<main>".to_string());
    }
    path.rsplit('/').next().unwrap_or(&path).to_string()
}

/// Map each address to the module whose code contains it.
fn locate(ips: &[usize]) -> (Vec<Module>, Vec<Option<Located>>) {
    let mut modules = Vec::new();
    let mut located: Vec<Option<Located>> = ips.iter().map(|_| None).collect();
    TargetSharedLibrary::each(|lib| {
        let mut index = None;
        for (ip, slot) in ips.iter().zip(located.iter_mut()) {
            if slot.is_some() {
                continue;
            }
            // A return address points past its call; step back into the call so the line is
            // the call's, not whatever follows it (which may even be another function).
            let avma = Avma(ip.saturating_sub(1));
            if !lib
                .segments()
                .any(|seg| seg.is_code() && seg.contains_avma(lib, avma))
            {
                continue;
            }
            let module = *index.get_or_insert_with(|| {
                modules.push(Module {
                    name: module_name(lib),
                    build_id: lib.id().map(|id| id.to_string()),
                });
                modules.len() - 1
            });
            *slot = Some(Located {
                module,
                svma: lib.avma_to_svma(avma).0,
            });
        }
    });
    (modules, located)
}

/// The symbolization section of a panic report for the stack `ips`.
fn report(ips: &[usize]) -> String {
    let (modules, located) = locate(ips);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ SYMBOLIZE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    );
    for (n, (ip, at)) in ips.iter().zip(&located).enumerate() {
        let _ = match at {
            Some(at) => writeln!(out, "  {n:>3}: {}+{:#x}", modules[at.module].name, at.svma),
            None => writeln!(out, "  {n:>3}: {ip:#x} (in no loaded module)"),
        };
    }
    let mut by_module: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for at in located.iter().flatten() {
        by_module.entry(at.module).or_default().push(at.svma);
    }
    let _ = writeln!(
        out,
        "\n  Resolve with the build's debug output (`<debug>` below):"
    );
    for (module, svmas) in by_module {
        let Module { name, build_id } = &modules[module];
        let addrs: Vec<String> = svmas.iter().map(|a| format!("{a:#x}")).collect();
        let _ = match build_id {
            Some(id) => writeln!(
                out,
                "  # {name}\n  llvm-symbolizer --debug-file-directory=<debug>/lib/debug --build-id={id} {}",
                addrs.join(" ")
            ),
            None => writeln!(
                out,
                "  # {name} (no build ID)\n  llvm-symbolizer --obj=<path to {name} with debug info> {}",
                addrs.join(" ")
            ),
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{frames, locate, report};

    #[test]
    fn the_callers_frame_is_found_in_the_test_binary() {
        let ips = frames();
        let (modules, located) = locate(&ips);
        let exe = std::env::current_exe().unwrap_or_else(|e| unreachable!("{e}"));
        let exe = exe
            .file_name()
            .unwrap_or_else(|| unreachable!())
            .to_string_lossy();
        // Frame 0 is inside `backtrace`; this test's own frame follows it, in the test binary.
        let mine = located
            .iter()
            .flatten()
            .find(|at| modules[at.module].name == exe)
            .unwrap_or_else(|| unreachable!("no frame in {exe}: {}", report(&ips)));
        assert_ne!(mine.svma, 0);
    }

    #[test]
    fn the_report_lists_every_frame_and_a_command_per_module() {
        let ips = frames();
        let text = report(&ips);
        let (modules, _) = locate(&ips);
        assert!(text.contains(&format!("{:>3}: ", ips.len() - 1)), "{text}");
        assert_eq!(
            text.matches("llvm-symbolizer ").count(),
            modules.len(),
            "{text}"
        );
    }

    #[test]
    fn an_address_outside_every_module_is_reported_raw() {
        let text = report(&[0x10]);
        assert!(text.contains("0x10 (in no loaded module)"), "{text}");
    }
}
