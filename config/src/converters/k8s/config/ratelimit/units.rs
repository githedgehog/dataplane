// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Kubernetes Quantity and metav1.Duration wire formats, with exact rate conversion.
//! See <https://pkg.go.dev/k8s.io/apimachinery/pkg/api/resource#Quantity> and
//! <https://pkg.go.dev/time#ParseDuration>.

use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum RateQuantity {
    Quantity(Quantity),
    Number(serde_json::Number),
}

impl RateQuantity {
    pub(super) fn tokens(&self, divisor: u64) -> Result<u64, String> {
        let text = match self {
            Self::Quantity(q) => q.0.clone(),
            Self::Number(n) => n.to_string(),
        };
        quantity_tokens(&text, divisor)
    }
}

fn decimal(text: &str) -> Result<(BigUint, usize), String> {
    let mut parts = text.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || integer.len() + fraction.len() == 0
        || !integer
            .bytes()
            .chain(fraction.bytes())
            .all(|c| c.is_ascii_digit())
    {
        return Err(format!("invalid decimal {text:?}"));
    }
    let digits = format!("{integer}{fraction}");
    let n = BigUint::parse_bytes(digits.as_bytes(), 10)
        .ok_or_else(|| format!("invalid decimal {text:?}"))?;
    Ok((n, fraction.len()))
}

fn ten_pow(exponent: usize) -> Result<BigUint, String> {
    let exponent = u32::try_from(exponent).map_err(|_| "quantity exponent is too large")?;
    Ok(BigUint::from(10u8).pow(exponent))
}

fn quantity_tokens(input: &str, divisor: u64) -> Result<u64, String> {
    let text = input.strip_prefix('+').unwrap_or(input);
    let end = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (mut numerator, fraction) = decimal(&text[..end])?;
    let suffix = &text[end..];
    let exponent: i64 = match suffix {
        "n" => -9,
        "u" => -6,
        "m" => -3,
        "" => 0,
        "k" => 3,
        "M" => 6,
        "G" => 9,
        "T" => 12,
        "P" => 15,
        "E" => 18,
        "Ki" | "Mi" | "Gi" | "Ti" | "Pi" | "Ei" => {
            let shift = match suffix {
                "Ki" => 10,
                "Mi" => 20,
                "Gi" => 30,
                "Ti" => 40,
                "Pi" => 50,
                _ => 60,
            };
            numerator <<= shift;
            0
        }
        s if s.starts_with(['e', 'E']) => s[1..]
            .parse()
            .map_err(|_| format!("invalid quantity suffix {suffix:?}"))?,
        _ => return Err(format!("invalid quantity suffix {suffix:?}")),
    };
    if numerator.is_zero() {
        return Err("rate must be positive".into());
    }
    let scale = exponent
        .checked_sub(i64::try_from(fraction).map_err(|_| "quantity is too long")?)
        .and_then(|x| x.checked_add(9))
        .ok_or("quantity exponent is too large")?;
    // Bound powers before allocating: only values up to i64::MAX can become a meter rate.
    let digits =
        i64::try_from(numerator.to_str_radix(10).len()).map_err(|_| "quantity is too long")?;
    if scale > 29 - digits {
        return Err("rate exceeds the supported limit of 2^63 - 1".into());
    }
    let nanos = if scale >= 0 {
        numerator * ten_pow(usize::try_from(scale).map_err(|_| "quantity exponent is too large")?)?
    } else if scale < -digits {
        BigUint::from(1u8)
    } else {
        let denominator =
            ten_pow(usize::try_from(-scale).map_err(|_| "quantity exponent is too large")?)?;
        // Quantity rounds positive values up to nanounit precision.
        (&numerator + &denominator - BigUint::from(1u8)) / denominator
    };
    let quantum = BigUint::from(divisor) * BigUint::from(1_000_000_000u64);
    if &nanos % &quantum != BigUint::zero() {
        return Err(if divisor == 8 {
            "rate must resolve to whole bytes per second"
        } else {
            "rate must resolve to whole packets per second"
        }
        .into());
    }
    if nanos > BigUint::from(i64::MAX as u64) * BigUint::from(1_000_000_000u64) {
        return Err("rate exceeds the supported limit of 2^63 - 1".into());
    }
    (nanos / quantum)
        .to_u64()
        .ok_or_else(|| "rate is too large".into())
}

pub(super) fn duration(input: &str) -> Result<Duration, String> {
    let mut text = input.strip_prefix('+').unwrap_or(input);
    let mut total = 0u64;
    if text.is_empty() {
        return Err("burst duration is empty".into());
    }
    while !text.is_empty() {
        let end = text
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(text.len());
        let (number, fraction) = decimal(&text[..end])?;
        text = &text[end..];
        let end = text
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(text.len());
        let unit = match &text[..end] {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000u64,
            other => return Err(format!("invalid duration unit {other:?}")),
        };
        let nanos = (number * BigUint::from(unit) / ten_pow(fraction)?)
            .to_u64()
            .ok_or("burst duration is too large")?;
        total = total
            .checked_add(nanos)
            .filter(|n| i64::try_from(*n).is_ok())
            .ok_or("burst duration exceeds metav1.Duration range")?;
        text = &text[end..];
    }
    if total == 0 {
        return Err("burst duration must be positive".into());
    }
    Ok(Duration::from_nanos(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_quantities_are_exact() {
        for (text, expected) in [
            ("1.5G", 1_500_000_000),
            ("1.5Gi", 1_610_612_736),
            ("8e6", 8_000_000),
            ("8E+6", 8_000_000),
            ("8000m", 8),
            ("8000000u", 8),
            ("8000000000n", 8),
            (".008k", 8),
            ("+8.", 8),
            ("0.9999999999", 1),
            ("9007199254740993", 9_007_199_254_740_993),
        ] {
            assert_eq!(quantity_tokens(text, 1).unwrap(), expected, "{text}");
        }
        assert_eq!(quantity_tokens("1.5Gi", 8).unwrap(), 201_326_592);
        for text in [
            "",
            "k",
            "1K",
            "1e3k",
            "NaN",
            "inf",
            "1.2.3",
            "-1",
            "0",
            "1e99999999",
            "1e-99999999",
            "0.1",
            "9223372036854775808",
        ] {
            assert!(quantity_tokens(text, 1).is_err(), "{text}");
        }
        assert!(quantity_tokens("9", 8).is_err());
    }

    #[test]
    fn kubernetes_durations_support_compounds_and_unicode_units() {
        for (text, nanos) in [
            ("100ms", 100_000_000),
            ("0.1s", 100_000_000),
            ("1m30.5s", 90_500_000_000),
            ("1h2m3s4ms5us6ns", 3_723_004_005_006),
            ("1µs", 1000),
            ("1μs", 1000),
            ("+1.5ms", 1_500_000),
            (".5s", 500_000_000),
            ("2562047h47m16.854775807s", 9_223_372_036_854_775_807),
        ] {
            assert_eq!(duration(text).unwrap().as_nanos(), nanos, "{text}");
        }
        for text in [
            "",
            "0",
            "0s",
            "-1s",
            "10",
            "1d",
            "1 s",
            "1e3s",
            "1s garbage",
            "2562048h",
            "µ",
            "1μ",
        ] {
            assert!(duration(text).is_err(), "{text}");
        }
    }

    #[test]
    fn arbitrary_input_never_panics() {
        bolero::check!().with_type::<String>().for_each(|text| {
            let _ = quantity_tokens(text, 8);
            let _ = duration(text);
        });
    }
}
