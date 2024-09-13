# Builds the mdbook-alerts package for use in the mdbook preprocessor
# I like this more than mdbook-admonish in that it uses the same syntax as
# github (which makes our docs more portable)
{ lib
, stdenv
, rustPlatform
, fetchFromGitHub
, CoreServices
}: rustPlatform.buildRustPackage rec {
  owner = "daniel-noland";
  pname = "mdbook-citeproc";
  version = "0.0.11";

  src = fetchFromGitHub {
  	inherit owner;
    repo = pname;
    rev = "v${version}";
    sha256 = "sha256-vgXlJ43gtc2R8UTH1Xo/xuAlGhPVypZWHWdM4Vd6SRk=";
  };

  cargoHash = "sha256-7/y7khfBakO+3IkRcpZUUMAc4rUM52w2/B2Jl9+7xMU=";

  buildInputs = lib.optionals stdenv.isDarwin [
	CoreServices
  ];

  meta = {
    description = "mdBook preprocessor to add citations to a book";
    mainProgram = "mdbook-citeproc";
    homepage = "https://github.com/${owner}/${pname}";
  };
}
