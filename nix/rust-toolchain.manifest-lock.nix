let
  rust-toolchain = (builtins.fromTOML (builtins.readFile ../rust-toolchain.toml)).toolchain;
  channel = rust-toolchain.channel;
  url = "https://static.rust-lang.org/dist/channel-rust-${channel}.toml";
  manifest-path = builtins.fetchurl {
    inherit url;
    name = "manifest.toml";
  };
  hash = {
    md5 = builtins.hashFile "md5" manifest-path;
    sha1 = builtins.hashFile "sha1" manifest-path;
    sha256 = builtins.hashFile "sha256" manifest-path;
    sha512 = builtins.hashFile "sha512" manifest-path;
  };
in
{
  inherit channel url hash;
}
