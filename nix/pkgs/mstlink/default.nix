# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#
# mstflint reduced to `mstlink` and the register database it reads at run time.
#
# The dataplane runs `mstlink --json` for the link diagnostics ConnectX firmware keeps in
# registers reachable only through PCI configuration space. The full mstflint closure is about
# 300 MiB, mostly python and curl for tools the dataplane never runs; this is about a fifth of
# that, nearly all of it libraries the image ships anyway.
{
  lib,
  mstflint,
  boost,
  expat,
  xz,
}:
(mstflint.override {
  # Drops python, curl and the firmware tools from the build...
  onlyFirmwareUpdater = true;
  enableDPA = false;
}).overrideAttrs
  (prev: {
    pname = "mstlink";
    # ...and this brings back what mstlink alone needs. rdma-core is only for in-band access, over
    # InfiniBand verbs; mstlink reads PCI configuration space. It also drags systemd into the
    # build, which does not cross-build for musl.
    buildInputs = lib.filter (input: (input.pname or "") != "rdma-core") prev.buildInputs ++ [
      boost
      expat
      xz
    ];
    configureFlags = prev.configureFlags ++ [
      "--enable-adb-generic-tools"
      "--disable-inband"
    ];
    # mstlink finds its register database under this package's prefix, so it stays in place; the
    # databases for switches and GPUs, and every other tool, go.
    postInstall = (prev.postInstall or "") + ''
      find $out/bin -mindepth 1 ! -name mstlink -delete
      find $out/share/mstflint -mindepth 1 -maxdepth 1 ! -name prm_dbs -exec rm -rf {} +
      find $out/share/mstflint/prm_dbs -mindepth 1 -maxdepth 1 ! -name hca -exec rm -rf {} +
      rm -rf $out/lib $out/include $out/etc $out/share/man $out/share/doc
    '';
  })
