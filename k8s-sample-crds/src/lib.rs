// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tiny crate to automatically generate JSON/YAML CRD templates
//! These are mostly for manual testing.

#[cfg(test)]
mod test {
    use k8s_intf::utils::load_crd_from_file;

    #[test]
    fn test_load_crd_from_file() {
        let crd_from_json = load_crd_from_file("generated-samples/sample.yaml").unwrap();
        let crd_from_yaml = load_crd_from_file("generated-samples/sample.json").unwrap();

        assert_eq!(crd_from_json, crd_from_yaml);
    }
}
