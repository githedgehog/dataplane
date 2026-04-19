# Install a prebuilt zot binary from upstream GitHub releases.  The project
# ships statically-linked linux/amd64 binaries per release; we fetch the asset
# directly rather than rebuild it from source.
#
# Versioning: the tag name (e.g. "v2.1.15") comes from the npins `zot` pin,
# so a plain `npins update` (i.e. `just bump pins`) bumps the version.
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
  pname = "zot";
  # src.version carries the tag (e.g. "v2.1.15"); strip the leading "v" so
  # the derivation name reads as a plain version.
  version = lib.removePrefix "v" src.version;

  src = fetchurl {
    url = "https://github.com/project-zot/zot/releases/download/${src.version}/zot-linux-amd64";
    hash = lib.removeSuffix "\n" (builtins.readFile ./binary.sri);
  };

  dontUnpack = true;
  dontStrip = true;
  dontConfigure = true;
  dontBuild = true;

  # zot ships a statically-linked Go binary, so autoPatchelfHook has nothing
  # to patch; it's kept as a safety net in case upstream ever switches to a
  # dynamically-linked build.
  nativeBuildInputs = [ autoPatchelfHook ];

  installPhase = ''
    runHook preInstall
    install -Dm755 $src $out/bin/zot
    runHook postInstall
  '';

  meta = {
    description = "OCI-native container image registry";
    homepage = "https://zotregistry.dev";
    license = lib.licenses.asl20;
    mainProgram = "zot";
    platforms = [ "x86_64-linux" ];
  };
}
