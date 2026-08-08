# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Fetches a pinned Flatcar release and repackages it into the layout the
# kernel manifest expects.
#
# The point of running tests against this kernel is that our own is built
# from a minimal config we chose, so it cannot tell us whether the code
# works on the kernel we actually ship.  This one can.
#
# # Why the PXE cpio rather than the disk image
#
# The modules live inside the `/usr` filesystem, and there are two published
# artifacts carrying it.  The disk image is a GPT-partitioned,
# dm-verity-protected ext4 volume: reading it means slicing the partition
# out by offset and coping with the verity hash tree, and mounting is not an
# option because nix builds run unprivileged and cannot `mount -o loop`.
#
# The PXE cpio contains exactly three entries -- `.`, `etc`, and
# `usr.squashfs` -- so the whole extraction is `cpio -i` then `unsquashfs`,
# both of which are ordinary userspace tools needing no privileges.  It is
# also the smaller download.
#
# # Why the fetches are separate derivations
#
# So that the ~400 MB of upstream artifacts are inputs to *this* derivation
# rather than part of its output.  Nix substituters match on the output
# hash, so a consumer whose pin is unchanged gets the repackaged result from
# the binary cache and never realises the fetches at all.  The download
# happens once, wherever this is first built.
{
  lib,
  stdenvNoCC,
  fetchurl,
  cpio,
  squashfsTools,
  gzip,
  # `scripts/extract-ikconfig` from any kernel source tree.  The script is
  # version-agnostic: it scans an image for the embedded `IKCFG_ST` block,
  # so our own kernel's copy reads Flatcar's image perfectly well.
  extractIkconfig,

  # Flatcar release to pin.  Both artifacts must come from the same one:
  # modules are vermagic-matched to their kernel and will refuse to load
  # against a different build.
  channel ? "stable",
  version ? "4593.2.4",
  # Digests are published as SHA512 in the `.DIGESTS` files beside each
  # artifact; there is no SHA256 to use instead.
  vmlinuzHash ? "sha512-nwL0g+WSR60foPWju9IyuGAF5xv2qDnNBdn5MXO3UUNXFa8/DKYbgzlkJ0FrOQ0PRqP+bX2zZaWzboIHQQ8dHg==",
  pxeImageHash ? "sha512-iALhDGwMNfvjbmD7sXJWqQs7zLhxD9bque93PXPTqVAMfSVYpqtRuX/HEy3PKepDmb2rm05xYEzqKnjppCjv0w==",
}:
let
  # The versioned CDN path, not `.../current/`.  `current` moves at every
  # release, so a pin against it would keep a valid hash while silently
  # coming to mean a different kernel.
  base = "https://flatcar.cdn.cncf.io/${channel}/amd64-usr/${version}";

  vmlinuz = fetchurl {
    url = "${base}/flatcar_production_pxe.vmlinuz";
    hash = vmlinuzHash;
  };

  pxeImage = fetchurl {
    url = "${base}/flatcar_production_pxe_image.cpio.gz";
    hash = pxeImageHash;
  };
in
stdenvNoCC.mkDerivation {
  pname = "flatcar-kernel";
  inherit version;

  dontUnpack = true;
  dontConfigure = true;
  dontFixup = true;

  nativeBuildInputs = [
    cpio
    gzip
    squashfsTools
  ];

  buildPhase = ''
    runHook preBuild

    # The cpio holds one large file; stream it rather than materialising
    # the archive twice.
    mkdir -p extracted
    ( cd extracted && gzip -dc ${pxeImage} | cpio -idm --quiet usr.squashfs )

    # Selective extraction: the squashfs is the whole of /usr (~393 MB) and
    # the module tree is the only part any of this needs.
    # `-no-xattrs` because the tree carries `security.selinux` attributes
    # that only root may set, and a nix build is unprivileged.  They are of
    # no use to us either way: the guest never enforces SELinux, and the
    # modules only have to be readable.
    unsquashfs -quiet -no-progress -no-xattrs \
      -dest usr extracted/usr.squashfs 'lib/modules'
    rm -rf extracted

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out
    cp ${vmlinuz} $out/vmlinuz

    # The kernel version is discovered rather than assumed: it is a property
    # of the release, and hardcoding it would break silently on a version
    # bump -- the modules would be present but under a directory nothing
    # looks in.
    modDir=$(ls usr/lib/modules)
    if [ "$(printf '%s\n' "$modDir" | wc -l)" != 1 ]; then
      echo "expected exactly one module directory, found: $modDir" >&2
      exit 1
    fi
    echo "$modDir" > $out/mod-dir-version

    # `lib/modules/<ver>`, matching both nixpkgs' `modules` output and what
    # `modprobe --dirname` expects, so neither consumer needs to know which
    # kind of kernel produced the tree.
    mkdir -p $out/lib/modules
    cp -r usr/lib/modules/"$modDir" $out/lib/modules/"$modDir"
    chmod -R u+w $out/lib/modules

    # `CONFIG_IKCONFIG=y` means the complete, post-resolution config is
    # embedded in the image, so it can be recovered here rather than at boot
    # -- which is what lets a test's declared kernel requirements be checked
    # before a VM is started.
    ${extractIkconfig} $out/vmlinuz > $out/config
    if ! grep -q '^CONFIG_' $out/config; then
      echo "extract-ikconfig produced no config; is CONFIG_IKCONFIG set?" >&2
      exit 1
    fi

    runHook postInstall
  '';

  meta = {
    description = "Flatcar ${channel} ${version} kernel, modules and config";
    # The kernel and its modules are GPL-2.0-only; the surrounding release
    # is Apache-2.0.  Only the kernel parts are repackaged here.
    license = lib.licenses.gpl2Only;
    platforms = [ "x86_64-linux" ];
  };
}
