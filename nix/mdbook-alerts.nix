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
  version = "0.6.4";

  src = fetchFromGitHub {
  	inherit owner;
  	repo = pname;
    rev = "v${version}";
    hash = "sha256-bg3X7M2H553tGxH8cEkkT0XK20fWwkp2nTVEgtZ819s=";
  };

  cargoHash = "sha256-N4fSfTOocWW9RbpAc137wcehUm+j5onKGJBFL8LzwQw=";

  buildInputs = lib.optionals stdenv.isDarwin [
    CoreServices
  ];

  meta = {
    description = "mdBook preprocessor to add GitHub Flavored Markdown's Alerts to your book";
    mainProgram = "mdbook-alerts";
    homepage = "https://github.com/${owner}/${pname}";
  };
}