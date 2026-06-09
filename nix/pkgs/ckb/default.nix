# Build CKB (Code Knowledge Base) from source with CGO enabled.
#
# The npm-distributed binary (`npx @tastehub/ckb`) is upstream's `build-fast`
# variant: CGO_ENABLED=0 and no `-tags cartographer`.  That compiles out the
# tree-sitter AST analyzers -- the `internal/complexity` and bug-pattern code
# is `//go:build cgo`, with a `!cgo` stub -- so `ckb review` reports
# "Complexity analysis not available (tree-sitter not built)".
#
# We build with CGO on so complexity analysis works.  It is Rust-aware:
# internal/complexity/treesitter.go imports go-tree-sitter's rust grammar and
# dispatches `LangRust`.  (Bug-pattern detection uses Go-specific node types,
# so it stays Go-only -- harmless but of no value on this Rust repo.)
#
# NOT enabled here: the cartographer backend (layers / arch-health).  That is
# a `-tags cartographer` build that links a Rust static lib (libcartographer.a)
# via CGO and is a much heavier derivation; deferred until the complexity
# analysis proves its worth.
#
# Versioning: the tag (e.g. "v9.2.0") comes from the npins `ckb` pin, so
# `just bump pins` bumps the version.
{
  lib,
  buildGoModule,
  src,
}:
buildGoModule {
  pname = "ckb";
  # src.version carries the tag (e.g. "v9.2.0"); strip the leading "v".
  version = lib.removePrefix "v" src.version;
  src = src.outPath;

  # go-tree-sitter bundles its C grammars and is only compiled under CGO.
  # GOTOOLCHAIN=local keeps the build hermetic: never fetch a toolchain even
  # if go.mod's directive outpaces the pinned Go (it currently asks for
  # 1.26.2; the pinned toolchain is 1.26.3).
  env = {
    CGO_ENABLED = "1";
    GOTOOLCHAIN = "local";
  };

  vendorHash = "sha256-jUUW9S2FTqUfcsh7YMkrmvJdlGUhs1r+F4VYaaD9NhY=";

  # Only the CLI/MCP entry point; pulls in internal/complexity et al.
  subPackages = [ "cmd/ckb" ];

  # Upstream's suite expects fixtures and network; not relevant to packaging.
  doCheck = false;

  ldflags = [
    "-s"
    "-w"
  ];

  meta = {
    description = "Code Knowledge Base: code intelligence for AI assistants (MCP/CLI), built with CGO for tree-sitter complexity analysis";
    homepage = "https://codeknowledge.dev";
    mainProgram = "ckb";
    platforms = lib.platforms.linux;
  };
}
