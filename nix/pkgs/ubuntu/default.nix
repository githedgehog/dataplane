# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Fetches a pinned Ubuntu kernel and repackages it into the layout the
# kernel manifest expects -- the same output shape as `pkgs/flatcar`.
#
# A second distro kernel is not redundant with the first.  Flatcar is the
# kernel we ship on, so it answers "does this work where we deploy".  This
# one answers a different question: whether the harness is actually
# distro-agnostic, or merely Flatcar-shaped.  Three of its assumptions turn
# out not to survive contact with a second distro -- see below -- and each
# was found by trying rather than by reading.
#
# # Why three packages
#
# Ubuntu splits what Flatcar ships together:
#
#   - `linux-image-unsigned-*` holds literally three files, one of which is
#     the kernel.  Not the signed `linux-image-*`: the signature wraps the
#     image for Secure Boot and buys nothing here, since QEMU is told to boot
#     it directly.
#   - `linux-modules-*` holds the module tree (~6900 modules).
#   - `linux-buildinfo-*` holds the config, and is the only place it exists.
#
# That last one is the interesting break.  Flatcar's package recovers the
# config *from the image* with `scripts/extract-ikconfig`, which works
# because Flatcar sets `CONFIG_IKCONFIG=y`.  Ubuntu does not
# (`# CONFIG_IKCONFIG is not set`), so that mechanism fails outright -- and
# the config is not optional here, because it is what a test's declared
# kernel requirements are checked against before a VM is started.
#
# # Why depmod runs here
#
# Ubuntu ships no `modules.dep`: it runs `depmod` from the package's
# postinst, on the installed system.  There is no postinst in a nix build,
# so the tree arrives unindexed and `modprobe --show-depends` -- which is
# how the initramfs discovers the module load order -- has nothing to read.
# Flatcar ships a fully indexed tree, so nothing needed this before.
#
# # Why the fetches are separate derivations
#
# So that the ~180 MB of upstream artifacts are inputs to *this* derivation
# rather than part of its output, and a consumer whose pin is unchanged gets
# the repackaged result from a substituter without realising the fetches.
# Same reasoning as `pkgs/flatcar`.
{
  lib,
  stdenvNoCC,
  fetchurl,
  dpkg,
  kmod,

  # The npins `url` pins (`ubuntu-kernel-image`, `ubuntu-kernel-modules`,
  # `ubuntu-kernel-buildinfo`) for the three packages; only their `url` and
  # `hash` are read.  `scripts/ubuntu-kernel-pins.sh` writes all three from
  # one build, at their versioned pool paths, after checking each against
  # the SHA256 the archive's `Packages` index publishes.
  #
  # The pool retains many kernel versions, but not indefinitely; when a pin
  # stops resolving, rerun the script, or for an older build use
  # `https://snapshot.ubuntu.com/ubuntu/<timestamp>/...`, which serves the
  # archive as it stood at a point in time.
  imagePin,
  modulesPin,
  buildinfoPin,
}:
let
  # The build is read back out of the pinned URLs, which end in
  # `<package>-<release>_<abi>_amd64.deb`: `release` names the module
  # directory (`7.0.0-29-generic`) and `abi` is the ABI-and-upload version
  # (`7.0.0-29.29`).
  build =
    package: pin:
    let
      parts = builtins.match ".*/${package}-([^_]+)_([^_]+)_amd64\\.deb" pin.url;
    in
    if parts == null then
      throw "unexpected Ubuntu kernel pin URL ${pin.url}; rerun scripts/ubuntu-kernel-pins.sh"
    else
      {
        release = builtins.elemAt parts 0;
        abi = builtins.elemAt parts 1;
      };

  # All three packages must come from the same build: modules are
  # vermagic-matched to their kernel and will refuse to load against a
  # different one, and a config from another build would describe a kernel
  # we are not running.
  inherit (build "linux-image-unsigned" imagePin) release abi;
  _sameBuild =
    (
      build "linux-modules" modulesPin == {
        inherit release abi;
      }
      && build "linux-buildinfo" buildinfoPin == { inherit release abi; }
    )
    || throw "Ubuntu kernel pins come from different builds (${imagePin.url}, ${modulesPin.url}, ${buildinfoPin.url}); rerun scripts/ubuntu-kernel-pins.sh";

  image = fetchurl {
    inherit (imagePin) url hash;
  };

  modules = fetchurl {
    inherit (modulesPin) url hash;
  };

  buildinfo = fetchurl {
    inherit (buildinfoPin) url hash;
  };
in
assert _sameBuild;
stdenvNoCC.mkDerivation {
  pname = "ubuntu-kernel";
  version = abi;

  dontUnpack = true;
  dontConfigure = true;
  # The module tree is someone else's build output: stripping or patching
  # ELF in it would invalidate the signatures and the vermagic.
  dontFixup = true;

  nativeBuildInputs = [
    dpkg
    kmod
  ];

  buildPhase = ''
    runHook preBuild

    # `dpkg-deb -x` needs no privileges, which is what makes a .deb an
    # easier upstream artifact than Flatcar's dm-verity-protected disk
    # image.
    mkdir -p stage
    for deb in ${image} ${modules} ${buildinfo}; do
      dpkg-deb -x "$deb" stage
    done

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out

    cp stage/boot/vmlinuz-${release} $out/vmlinuz

    # Ubuntu is usrmerged, so the tree arrives under `usr/lib`.  It is
    # published at `lib/modules/<version>` to match both nixpkgs' `modules`
    # output and what `modprobe --dirname` expects, so no consumer has to
    # know which distro produced the tree.
    mkdir -p $out/lib/modules
    cp -r stage/usr/lib/modules/${release} $out/lib/modules/${release}
    chmod -R u+w $out/lib/modules

    # The config exists only in the buildinfo package; there is no
    # `CONFIG_IKCONFIG` to recover it from the image.
    cp stage/usr/lib/linux/${release}/config $out/config
    if ! grep -q '^CONFIG_' $out/config; then
      echo "buildinfo config looks wrong: no CONFIG_ lines" >&2
      exit 1
    fi

    # Discovered rather than restated, so a version bump cannot leave the
    # modules under a directory nothing reads.
    modDir=$(ls $out/lib/modules)
    if [ "$(printf '%s\n' "$modDir" | wc -l)" != 1 ]; then
      echo "expected exactly one module directory, found: $modDir" >&2
      exit 1
    fi
    echo "$modDir" > $out/mod-dir-version

    # Build the index Ubuntu leaves to its postinst.  Without it,
    # `modprobe --show-depends` cannot answer, and the initramfs would be
    # assembled with no modules and panic looking for its root.
    depmod --basedir $out "$modDir"
    if [ ! -s $out/lib/modules/"$modDir"/modules.dep ]; then
      echo "depmod produced no modules.dep" >&2
      exit 1
    fi

    rm -rf stage

    runHook postInstall
  '';

  meta = {
    description = "Ubuntu ${release} (${abi}) kernel, modules and config";
    # The kernel and its modules are GPL-2.0-only.
    license = lib.licenses.gpl2Only;
    platforms = [ "x86_64-linux" ];
  };
}
