# Install a prebuilt opengrep binary from upstream GitHub releases.  Since
# v2.0.0 the project ships one statically-linked binary per platform
# (opengrep_linux_x86; the manylinux / musllinux assets are gone).
# autoPatchelfHook is kept so that a dynamically-linked asset would still
# run in our dev shell and CI environments.
#
# Versioning: the tag name (e.g. "v2.0.0") comes from the npins `opengrep`
# pin, so a plain `npins update` (i.e. `just bump pins`) bumps the version.
# The release asset is a raw ELF binary (no archive), which npins' tarball
# pin type rejects, so the binary's content hash is carried in ./binary.sri
# and is refreshed by scripts/bump.sh on every `just bump pins`.
{
  stdenvNoCC,
  fetchurl,
  autoPatchelfHook,
  lib,
  src,
}:
stdenvNoCC.mkDerivation {
  pname = "opengrep";
  # src.version carries the tag (e.g. "v2.0.0"); strip the leading "v" so
  # the derivation name reads as a plain version.
  version = lib.removePrefix "v" src.version;

  src = fetchurl {
    url = "https://github.com/opengrep/opengrep/releases/download/${src.version}/opengrep_linux_x86";
    hash = lib.removeSuffix "\n" (builtins.readFile ./binary.sri);
  };

  dontUnpack = true;
  dontStrip = true;
  dontConfigure = true;
  dontBuild = true;

  nativeBuildInputs = [ autoPatchelfHook ];

  installPhase = ''
    runHook preInstall
    install -Dm755 $src $out/bin/opengrep
    runHook postInstall
  '';

  meta = {
    description = "Open-source fork of Semgrep for pattern-based static analysis";
    homepage = "https://github.com/opengrep/opengrep";
    license = lib.licenses.lgpl21;
    mainProgram = "opengrep";
    platforms = [ "x86_64-linux" ];
  };
}
