// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared test-name extraction for host and container tiers.

/// Resolved identity for a test function.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TestIdentity {
    /// The fully-qualified type name after `&`-stripping.
    #[allow(dead_code)]
    pub full_type_name: &'static str,

    /// The portion passed to the Rust test harness with `--exact`.
    pub test_name: &'static str,
}

impl TestIdentity {
    /// Resolves the test identity from a function type parameter.
    ///
    /// Function item type names are expected to be fully qualified
    /// (`crate::module::test_fn`); the leading crate segment is stripped
    /// to produce the `--exact` test name.  `type_name` is documented as
    /// best-effort with no format guarantee, so a name without `::` is
    /// used as-is rather than treated as unreachable -- a wrong-but-
    /// diagnosable test name beats a panic in the harness.
    pub fn resolve<F>() -> Self {
        let full_type_name = std::any::type_name::<F>().trim_start_matches('&');
        let test_name = full_type_name
            .split_once("::")
            .map_or(full_type_name, |(_, rest)| rest);
        Self {
            full_type_name,
            test_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_test_function() {}

    fn resolve_for<F>(_: F) -> TestIdentity {
        TestIdentity::resolve::<F>()
    }

    #[test]
    fn resolve_produces_expected_test_name() {
        let id = resolve_for(dummy_test_function);
        assert!(
            id.full_type_name.contains("::"),
            "full_type_name should contain '::': {:?}",
            id.full_type_name,
        );
        assert!(
            !id.full_type_name.starts_with('&'),
            "full_type_name should not start with '&': {:?}",
            id.full_type_name,
        );
        assert!(
            id.full_type_name.ends_with(id.test_name),
            "full_type_name {:?} should end with test_name {:?}",
            id.full_type_name,
            id.test_name,
        );
    }

    #[test]
    fn resolve_with_concrete_function_item() {
        let id = resolve_for(dummy_test_function);
        assert!(
            id.test_name.ends_with("dummy_test_function"),
            "test_name should end with 'dummy_test_function': {:?}",
            id.test_name,
        );
    }
}
