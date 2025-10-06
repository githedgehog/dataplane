# Documentation Guidelines for AI Assistants

Remember that documentation degrades over time without maintenance.
Design your documentation to be maintainable.

## Basic guidelines

- **Keep documentation brief** - Concise documentation reduces maintenance burden and improves clarity.
- **Document rationale over implementation** - Explain "why" a design decision was made rather than "what" the code
  does.
  If your code is incomprehensible then documentation won't fix it.
- **Line breaks in between sentences** - This makes diffs easier to understand and discuss.
- **Try to satisfy linting rules** - Ensure documentation is free of linting errors.
  - The `.markdownlint.json` file may be adjusted if the rules proves overly restrictive, but try to avoid
    deactivating too many lints.
- **Prefer markdown shortcut links to inline links** - Use markdown shortcut syntax for links and images to make the
  documentation more readable and maintainable for humans.
  Inline links are disruptive to humans reading or editing the documentation as raw text.
  It is also easier to maintain the links when external resources change.

  **For example**

  ```markdown
  - This is an [inline markdown link example](https://www.markdownguide.org/basic-syntax/#links)
  - This is a [reference link][some-tag]
  - This is an [implicit link][]
  - This is an example of [markdown shortcut syntax]

  Shortcut links are like implicit links but lack the trailing `[]`.

  [some-tag]: https://www.markdownlang.com/basic/links.html#reference-style-links
  [implicit link]: https://www.markdownlang.com/basic/links.html#implicit-link-labels
  [markdown shortcut syntax]: https://www.markdownguide.org/basic-syntax/#links
  ```

  Reference links are also a good option, especially if the same document is referenced multiple times with differing
  link text.

## Cross-References

- **Create hyperlinks between related documentation** - Connect rustdoc pages and markdown files to provide complete
  context.
- **Follow rustdoc linking conventions** - Use proper syntax from the
  [linking rules for rustdoc](https://doc.rust-lang.org/rustdoc/write-documentation/linking-to-items-by-name.html).

  For example,

  ```rust
  /// Example function
  ///
  /// Returns as [`std::vec::Vec`]
  fn example_function() -> Vec<i32> {
      vec![1, 2, 3]
  }
  ```

## Diagrams

Consider including diagrams if you think it will make the docs

- more robust,
- more succinct,
- or more maintainable.

[If you think a diagram is useful, follow the guidelines.](./diagrams.md)

## Mathematical expressions

Consider including mathematical expressions if you think it will make the docs

- more robust,
- more succinct,
- or more maintainable.

If a relationship is best expressed using mathematical notation, [follow the guidelines](./math.md).
