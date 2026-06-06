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
    /// # Panics
    ///
    /// Panics (via `unreachable!`) if `type_name::<F>()` does not contain
    /// `::`.  This would indicate a change in the compiler's `type_name`
    /// format that breaks the invariant that function item type names are
    /// always fully qualified.
    pub fn resolve<F>() -> Self {
        let full_type_name = std::any::type_name::<F>().trim_start_matches('&');
        let (_, test_name) = full_type_name.split_once("::").unwrap_or_else(|| {
            unreachable!("std::any::type_name::<F>() did not contain '::': {full_type_name:?}")
        });
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
