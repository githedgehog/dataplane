# Modified mdbook

I made some modifications to the base mdbook setup to make it more suitable for scientific writing.
The main changes are:

1. Bibliography support using pandoc / citeproc.
2. Equation / figure numbering and references.
3. Greatly improved support for footnotes, end-notes, asides, and qualifications.
4. Support for glossaries.
5. Support for embedded YouTube videos.
6. Improved support for plantuml (linked diagrams are supported).
7. Revised page layout (I removed the left/right arrow bar and widened the page to make mobile reading easier).

## Building the book

It is possible to manually install all the needed dependencies and build the book, but it is much easier to use the provided [nix](https://nixos.org/) shell.

Once you have installed `nix`, you can build the book by running:

```bash
nix-build --attr book
```

or, if you are using nix flakes:

```bash
nix build
```

## Developing the book

I provided a nix shell that contains all the needed dependencies for developing the book. You can enter the shell by running:

```bash
nix-shell
```

or, if you are using nix flakes:

```bash
nix develop
```

Once you are in the shell, you can build the book by running:

```bash
cd src/mdbook
mdbook build && mdbook serve
```

Then open a web browser and navigate to `http://localhost:3000` to see the book.
The page should live update as you edit the markdown files.
