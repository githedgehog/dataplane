# Math expressions in rustdoc and markdown

- **Mathematical expressions** - Are not needed very often in our code base, but they can be embedded into rustdoc or
  project markdown files.
  Both inline and block math expressions are supported.
  - Inline math: Place LaTeX between dollar signs (`$...$`)
  - Block math: Use code fences with `math` language annotation

## Examples

Inline math is supported by enclosing $\LaTeX$ expressions between `$`s.
For example, the text `$E = \gamma(v) m c^2$` will render as $E = \gamma(v) m c^2$.

For larger expressions or when emphasis is needed, use the math block:

For example the text

````markdown
The Fourier transform is defined as

```math
\widehat{f}(\xi) = \int_{-\infty}^{\infty}\mathrm{d}x \cdot f(x) e^{-2\pi i \xi x}
```

````

will render as

The Fourier transform is defined as

```math
\widehat{f}(\xi) = \int_{-\infty}^{\infty}\mathrm{d}x \cdot f(x) e^{-2\pi i \xi x}
```
