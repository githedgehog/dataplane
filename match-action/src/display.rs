// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `Display` for the field specs, so that a rule can be rendered from its *typed* form.
//!
//! Rendering a rule from its erased [`FieldPredicate`](crate::FieldPredicate) bytes forces the
//! renderer to guess what each field means -- by byte width, or worse by field position. Printing
//! the typed spec instead means every field is formatted by the domain type that owns it (a VNI
//! prints as a VNI, an IP protocol as `TCP`), and reordering a key's fields can no longer silently
//! mislabel the output.

use core::fmt::{self, Display, Formatter};

use crate::IsUniversal;
use crate::field::FixedSize;
use crate::predicate::be_bytes;
use crate::rule::{ExactSpec, MaskSpec, PrefixSpec, RangeSpec};

/// A rule's fields, reachable one at a time.
///
/// The derived whole-rule `Display` renders every field into one finished string
/// (`proto=TCP, src_vni=100, ...`). That is fine for a one-rule-per-line dump and useless for a
/// columnar one: to pad a column you need each value's rendered width *before* you place it, and a
/// finished sentence cannot be measured field by field without taking it apart again on `", "` and
/// `"="` -- which would put the renderer back to guessing what each field means, exactly what
/// rendering from the typed form exists to avoid.
///
/// So the derive hands out the pieces instead. [`FIELD_NAMES`](RuleFields::FIELD_NAMES) is in key
/// order and indexes [`fmt_field`](RuleFields::fmt_field), so a caller can check that the fields
/// are the ones it expects rather than trusting position.
pub trait RuleFields {
    /// The name each field is displayed under, in key order.
    ///
    /// The field's own identifier, unless it carries `#[cli(column_name = "...")]` -- so a heading
    /// is declared next to the field it heads rather than in a table in the consumer.
    const FIELD_NAMES: &'static [&'static str];

    /// Render the field at `index`, or fail if there is no such field.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when `index` is out of range, or when the underlying field's own
    /// `Display` fails.
    fn fmt_field(&self, index: usize, f: &mut Formatter<'_>) -> fmt::Result;
}

/// One field of one rule, as something printable.
///
/// Honours width, fill and alignment, so a caller can pad with the ordinary formatting machinery
/// (`{:<12}`) rather than measuring and padding by hand:
///
/// ```ignore
/// write!(f, "{:<width$}", Field::of(rule, i))?;
/// ```
pub struct Field<'a, R: ?Sized> {
    rule: &'a R,
    index: usize,
}

impl<'a, R: RuleFields + ?Sized> Field<'a, R> {
    /// The field at `index` of `rule`.
    #[must_use]
    pub fn of(rule: &'a R, index: usize) -> Self {
        Self { rule, index }
    }
}

impl<R: RuleFields + ?Sized> Display for Field<'_, R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        struct Unpadded<'a, R: ?Sized>(&'a Field<'a, R>);
        impl<R: RuleFields + ?Sized> Display for Unpadded<'_, R> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                self.0.rule.fmt_field(self.0.index, f)
            }
        }
        // Rendered first so `pad` can apply the caller's width. `write!` rather than `to_string`,
        // which panics when a `Display` impl returns an error -- an out-of-range index is a caller
        // bug, and should not take down a CLI.
        let mut rendered = String::new();
        core::fmt::write(&mut rendered, format_args!("{}", Unpadded(self)))?;
        f.pad(&rendered)
    }
}

/// Render `rows` under `headings` as a fixed-width grid.
///
/// Every column is padded to the widest cell in it, headings included, and columns are separated by
/// two spaces. The last column is not padded, so lines carry no trailing whitespace.
///
/// # Errors
///
/// Returns [`fmt::Error`] if the underlying writer fails. Rows shorter than `headings` are padded
/// with blanks; longer rows have their surplus cells dropped, so a caller that miscounts gets a
/// ragged table rather than a panic.
pub fn write_grid<W: fmt::Write>(
    w: &mut W,
    headings: &[&str],
    rows: &[Vec<String>],
) -> fmt::Result {
    let width = |s: &str| s.chars().count();
    let cell = |row: &[String], i: usize| row.get(i).map_or("", String::as_str).to_string();

    let widths: Vec<usize> = headings
        .iter()
        .enumerate()
        .map(|(i, heading)| {
            rows.iter()
                .map(|row| width(&cell(row, i)))
                .chain(core::iter::once(width(heading)))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let last = headings.len().saturating_sub(1);
    let mut write_row = |cells: &dyn Fn(usize) -> String| -> fmt::Result {
        let mut line = String::new();
        for (i, column) in widths.iter().enumerate() {
            let text = cells(i);
            line.push_str(&text);
            if i != last {
                line.extend(core::iter::repeat_n(
                    ' ',
                    column.saturating_sub(width(&text)) + 2,
                ));
            }
        }
        writeln!(w, "{}", line.trim_end())
    };

    write_row(&|i| headings[i].to_string())?;
    for row in rows {
        write_row(&|i| cell(row, i))?;
    }
    Ok(())
}

impl<T: FixedSize + Display> Display for ExactSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.value, f)
    }
}

impl<T: FixedSize + Display> Display for PrefixSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.len)
    }
}

impl<T: FixedSize + Display + PartialEq> Display for RangeSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_universal() {
            f.write_str("*")
        } else if self.min == self.max {
            Display::fmt(&self.min, f)
        } else {
            write!(f, "{}..={}", self.min, self.max)
        }
    }
}

/// A mask with every bit significant prints as the bare value (`TCP`); one with no significant bit
/// prints as a wildcard (`*`).
///
/// A *partial* mask prints as `0x<value & mask>/0x<mask>`. Neither operand is a meaningful value of
/// `T` there, so neither is passed through `T`'s `Display`: a `NextHeader` of `TCP` under mask
/// `0xf0` matches every protocol `0x00..=0x0f`, and rendering it `TCP/0xf0` would name one
/// arbitrary member of the matched set as though it were the whole set.
///
/// The value is masked before rendering because that is precisely what both backends match on:
/// `rte_acl` ANDs the value with the mask when it builds the trie (`acl_gen_mask_trie`), and
/// [`Accepts`](crate::Accepts) compares `(field & mask)` against `(value & mask)`. Bits of `value`
/// outside the mask cannot change a lookup, so rendering them would show a distinction the
/// classifier does not make.
impl<T: FixedSize + Display> Display for MaskSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mask = be_bytes(&self.mask);
        if mask.iter().all(|byte| *byte == 0) {
            f.write_str("*")
        } else if mask.iter().all(|byte| *byte == u8::MAX) {
            Display::fmt(&self.value, f)
        } else {
            let value = be_bytes(&self.value);
            f.write_str("0x")?;
            value
                .iter()
                .zip(mask.iter())
                .try_for_each(|(value, mask)| write!(f, "{:02x}", value & mask))?;
            f.write_str("/0x")?;
            mask.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Accepts;
    use core::net::Ipv4Addr;

    #[test]
    fn exact_prints_the_value() {
        assert_eq!(ExactSpec::new(42u16).to_string(), "42");
    }

    #[test]
    fn prefix_prints_value_slash_length() {
        assert_eq!(
            PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8).to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn range_collapses_wildcard_and_singleton() {
        assert_eq!(RangeSpec::new(0u16, u16::MAX).to_string(), "*");
        assert_eq!(RangeSpec::exact(443u16).to_string(), "443");
        assert_eq!(RangeSpec::new(80u16, 8080u16).to_string(), "80..=8080");
    }

    #[test]
    fn mask_collapses_full_and_empty() {
        assert_eq!(MaskSpec::new(6u8, 0xffu8).to_string(), "6");
        assert_eq!(MaskSpec::new(0u8, 0x00u8).to_string(), "*");
        assert_eq!(MaskSpec::new(0xabu8, 0xf0u8).to_string(), "0xa0/0xf0");
    }

    /// A partial mask renders both operands as the bit patterns they are, over the field's full
    /// width, with the value's don't-care bits cleared.
    #[test]
    fn partial_mask_renders_as_bit_patterns() {
        assert_eq!(
            MaskSpec::new(0xabcdu16, 0xff00u16).to_string(),
            "0xab00/0xff00"
        );
    }

    /// Bits of `value` outside the mask cannot change a lookup, so two specs differing only in
    /// those bits accept exactly the same inputs -- asserted here rather than assumed -- and must
    /// therefore render identically. Were they to differ, the CLI dump would show an operator a
    /// distinction the classifier does not make.
    #[test]
    fn render_ignores_value_bits_outside_the_mask() {
        bolero::check!()
            .with_type::<(u8, u8)>()
            .for_each(|&(value, mask)| {
                let raw = MaskSpec::new(value, mask);
                let normalized = MaskSpec::new(value & mask, mask);
                for probe in 0..=u8::MAX {
                    assert_eq!(
                        raw.accepts(&probe),
                        normalized.accepts(&probe),
                        "masked-off bits changed what {raw:?} accepts"
                    );
                }
                assert_eq!(raw.to_string(), normalized.to_string());
            });
    }
}

#[cfg(test)]
mod field_and_grid_tests {
    use super::*;
    use crate::{MaskSpec, PrefixSpec, RangeSpec};
    use core::net::Ipv4Addr;

    /// A hand-written stand-in for a derived rule, so these tests exercise `RuleFields` without
    /// depending on the derive macro (which lives in a different crate and cannot be used here).
    struct Rule {
        proto: MaskSpec<u8>,
        dst_ip: PrefixSpec<Ipv4Addr>,
        dst_port: RangeSpec<u16>,
    }

    impl RuleFields for Rule {
        const FIELD_NAMES: &'static [&'static str] = &["proto", "dst_ip", "dst_port"];

        fn fmt_field(&self, index: usize, f: &mut Formatter<'_>) -> fmt::Result {
            match index {
                0 => Display::fmt(&self.proto, f),
                1 => Display::fmt(&self.dst_ip, f),
                2 => Display::fmt(&self.dst_port, f),
                _ => Err(fmt::Error),
            }
        }
    }

    fn rule() -> Rule {
        Rule {
            proto: MaskSpec::exact(6u8),
            dst_ip: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            dst_port: RangeSpec::exact(443u16),
        }
    }

    #[test]
    fn fields_render_individually_and_in_key_order() {
        let rule = rule();
        let rendered: Vec<String> = (0..Rule::FIELD_NAMES.len())
            .map(|i| Field::of(&rule, i).to_string())
            .collect();
        assert_eq!(rendered, ["6", "10.0.0.0/24", "443"]);
    }

    /// The point of the adapter: a caller can pad a field to a column width. Rendering through
    /// `fmt_field` directly would silently ignore the width, since padding is applied by the
    /// outermost `Display` and the field's own impl knows nothing about its column.
    #[test]
    fn a_field_honours_width_and_alignment() {
        let rule = rule();
        assert_eq!(format!("{:<8}|", Field::of(&rule, 1)), "10.0.0.0/24|");
        assert_eq!(format!("{:<14}|", Field::of(&rule, 1)), "10.0.0.0/24   |");
        assert_eq!(format!("{:>6}|", Field::of(&rule, 2)), "   443|");
    }

    #[test]
    fn an_out_of_range_field_fails_rather_than_panicking() {
        use core::fmt::Write;
        let mut sink = String::new();
        assert!(write!(sink, "{}", Field::of(&rule(), 3)).is_err());
    }

    #[test]
    fn grid_pads_every_column_to_its_widest_cell() {
        let mut out = String::new();
        write_grid(
            &mut out,
            &["rank", "destination", "NAT"],
            &[
                vec!["[0]".into(), "10.0.0.0/24".into(), "-".into()],
                vec!["[1]".into(), "1.2.3.4/32".into(), "masquerade".into()],
            ],
        )
        .unwrap();
        assert_eq!(
            out,
            "rank  destination  NAT\n\
             [0]   10.0.0.0/24  -\n\
             [1]   1.2.3.4/32   masquerade\n",
        );
    }

    /// The last column is not padded, so no line carries trailing whitespace -- which would
    /// otherwise show up as invisible diff noise the moment anyone captures this output.
    #[test]
    fn grid_leaves_no_trailing_whitespace() {
        let mut out = String::new();
        write_grid(
            &mut out,
            &["a", "bbbb"],
            &[
                vec!["x".into(), "y".into()],
                vec!["zz".into(), String::new()],
            ],
        )
        .unwrap();
        for line in out.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace in {line:?}");
        }
    }
}
