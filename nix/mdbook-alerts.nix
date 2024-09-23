# Builds the mdbook-alerts package for use in the mdbook preprocessor
# I like this more than mdbook-admonish in that it uses the same syntax as
# github (which makes our docs more portable)
{ lib
, stdenv
, fetchFromGitHub
, rustPlatform
, CoreServices
}: rustPlatform.buildRustPackage rec {
  owner = "lambdalisue";
  pname = "rs-mdbook-alerts";
  version = "0.6.7";

  src = fetchFromGitHub {
  	inherit owner;
  	repo = pname;
    rev = "v${version}";
    hash = "sha256-H3xpaluEUYWuP+JR4Zx8zs/EqeEZPiBa2wcaAtPdvGY=";
  };

  cargoHash = "sha256-46IcFR5tG/AH6/Hqvc+KL4wHi2hcrcW2rAvfQF9dr7A=";

  buildInputs = lib.optionals stdenv.isDarwin [
    CoreServices
  ];

  meta = {
    description = "mdBook preprocessor to add GitHub Flavored Markdown's Alerts to your book";
    mainProgram = "mdbook-alerts";
    homepage = "https://github.com/${owner}/${pname}";
  };
}
