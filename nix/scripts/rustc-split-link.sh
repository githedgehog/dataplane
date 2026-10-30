# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# The `RUSTC_WRAPPER` of a test archive whose links are bounded (see link-slots.sh).
#
# A link waiting for its slot is a rustc process that has finished compiling and is waiting on its
# linker, with its whole compilation session -- a gigabyte or two -- still resident. So for the
# crates that link (binaries and test harnesses), compile with `-Zno-link`, which writes the objects
# and an `.rlink` describing the link and then exits, freeing all of that; then link in a second,
# small rustc with `-Zlink-only`, given the same arguments with the `.rlink` in place of the source.
# Libraries, build scripts and cargo's own probes (`rustc -vV`) pass straight through. The `-Z`
# flags need `RUSTC_BOOTSTRAP=1`, which these builds set.

rustc="$1"
shift

links=false
name=
out_dir=
extra=
src=
prev=
for arg in "$@"; do
  case "${prev}" in
    --crate-name) name="${arg}" ;;
    --out-dir) out_dir="${arg}" ;;
    --crate-type) if [ "${arg}" = bin ]; then links=true; fi ;;
    -C) case "${arg}" in extra-filename=*) extra="${arg#extra-filename=}" ;; esac ;;
  esac
  case "${arg}" in
    --test | --crate-type=bin) links=true ;;
    -Cextra-filename=*) extra="${arg#-Cextra-filename=}" ;;
    --out-dir=*) out_dir="${arg#--out-dir=}" ;;
    *.rs) if [ -z "${src}" ] && [ -f "${arg}" ]; then src="${arg}"; fi ;;
  esac
  prev="${arg}"
done
# Build scripts link too, but natively, without LTO, and cargo runs them as soon as they are built.
case "${name}" in build_script_*) links=false ;; esac

if ! "${links}" || [ -z "${src}" ] || [ -z "${out_dir}" ] || [ -z "${name}" ]; then
  exec "${rustc}" "$@"
fi

"${rustc}" "$@" -Zno-link

rlink="${out_dir}/${name}${extra}.rlink"
if [ ! -f "${rlink}" ]; then
  printf 'rustc-split-link: -Zno-link left no %s\n' "${rlink}" >&2
  exit 1
fi

args=()
for arg in "$@"; do
  if [ "${arg}" = "${src}" ]; then
    args+=("${rlink}")
  else
    args+=("${arg}")
  fi
done
status=0
"${rustc}" "${args[@]}" -Zlink-only || status=$?
rm -f "${rlink}"
exit "${status}"
