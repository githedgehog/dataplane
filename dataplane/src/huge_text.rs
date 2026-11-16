// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Move the executable's code onto anonymous transparent huge pages. Bench only, opt-in.
//!
//! The hot path spans more code than the instruction TLB covers in 4 KiB pages. BOLT's `-hugify`
//! would back the text with huge pages, but on our kernels (no `READ_ONLY_THP_FOR_FS`) and
//! filesystems it does nothing: file-backed text never gets huge pages. Instead, copy the
//! 2 MiB-aligned part of the text into anonymous memory, collapse that into huge pages, and swap
//! it in place of the original with one `mremap`. The bytes at every address are the same before
//! and after, so it is safe even though this code runs inside the range it moves.
//! See notes/bolt-hugify.md (section 4a); this is its `remap.c` in Rust.
//!
//! Set `DATAPLANE_HUGE_TEXT=1` to enable. A profiler attached later (`perf record -p`) cannot
//! symbolize the moved range, so leave it off when collecting profiles.

#![allow(unsafe_code)] // raw mmap/mremap over our own text; see the module docs

use core::ffi::c_void;
use core::fmt::Write as _;

const HUGE: usize = 2 << 20;
/// `MADV_COLLAPSE` (Linux 6.1); not in every libc binding yet.
const MADV_COLLAPSE: libc::c_int = 25;

/// Remap the main executable's text, if `DATAPLANE_HUGE_TEXT=1`. Call first, before any thread.
pub fn remap_if_asked() {
    if std::env::var("DATAPLANE_HUGE_TEXT").as_deref() != Ok("1") {
        return;
    }
    let mut report = String::new();
    // SAFETY: the callback only reads the program headers it is handed, and remaps a range of
    // our own text with identical bytes.
    unsafe {
        libc::dl_iterate_phdr(Some(callback), (&raw mut report).cast());
    }
    eprintln!("huge_text: {report}");
}

unsafe extern "C" fn callback(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> libc::c_int {
    // SAFETY: the loader hands us a valid `dl_phdr_info` and `data` is our `String`.
    let (info, report) = unsafe { (&*info, &mut *data.cast::<String>()) };
    // SAFETY: `dlpi_phdr` points at `dlpi_phnum` program headers.
    let headers =
        unsafe { core::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)) };
    for ph in headers {
        if ph.p_type != libc::PT_LOAD || ph.p_flags & libc::PF_X == 0 {
            continue;
        }
        #[allow(clippy::cast_possible_truncation)] // 64-bit only
        let lo = info.dlpi_addr as usize + ph.p_vaddr as usize;
        #[allow(clippy::cast_possible_truncation)]
        let hi = lo + ph.p_memsz as usize;
        let a = (lo + HUGE - 1) & !(HUGE - 1);
        let b = hi & !(HUGE - 1);
        if b <= a {
            let _ = write!(report, "text {lo:#x}-{hi:#x} holds no whole huge page; ");
            continue;
        }
        let len = b - a;
        // SAFETY: fresh anonymous mappings; `a..b` is our own mapped text.
        unsafe {
            let raw = libc::mmap(
                core::ptr::null_mut(),
                len + HUGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if raw == libc::MAP_FAILED {
                report.push_str("mmap failed; ");
                return 1;
            }
            let raw = raw.cast::<u8>();
            let staged = ((raw as usize + HUGE - 1) & !(HUGE - 1)) as *mut u8;
            if staged > raw {
                libc::munmap(raw.cast(), staged as usize - raw as usize);
            }
            let end = raw as usize + len + HUGE;
            if staged as usize + len < end {
                libc::munmap(staged.add(len).cast(), end - (staged as usize + len));
            }
            libc::madvise(staged.cast(), len, libc::MADV_HUGEPAGE);
            core::ptr::copy_nonoverlapping(a as *const u8, staged, len);
            let collapse = libc::madvise(staged.cast(), len, MADV_COLLAPSE);
            libc::mprotect(staged.cast(), len, libc::PROT_READ | libc::PROT_EXEC);
            let moved = libc::mremap(
                staged.cast(),
                len,
                len,
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
                a as *mut c_void,
            );
            let _ = write!(
                report,
                "{a:#x}-{b:#x} ({} MiB) -> anonymous huge pages (collapse={collapse}, mremap={}); ",
                len >> 20,
                if moved == a as *mut c_void {
                    "ok"
                } else {
                    "FAILED"
                }
            );
        }
    }
    1 // the main executable comes first; stop there
}
