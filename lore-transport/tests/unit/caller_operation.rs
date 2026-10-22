// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use lore_transport::caller_operation::canonical_endpoint;
use lore_transport::caller_operation::is_legacy_fragment_put;
use lore_transport::caller_operation::recovery_dial_url;
use lore_transport::caller_operation::recovery_receipt_method_matches;

/// Only the fragment Put an older build journaled is legacy; every other storage child stays
/// journaled and so must not be mistaken for it.
#[test]
fn only_the_exact_fragment_put_is_a_legacy_unjournaled_child() {
    assert!(is_legacy_fragment_put("StorageService.Put"));
    for other in [
        "",
        "StorageService.PutResolved",
        "StorageService.Copy",
        "StorageService.Verify",
        "StorageService.MutableStore",
        "StorageService.MutableCompareAndSwap",
        "RevisionService.BranchPush",
        "RevisionService.BranchCreate",
        "LockService.Lock",
        "StorageService.Put ",
        "storageservice.put",
        "Put",
    ] {
        assert!(!is_legacy_fragment_put(other), "{other:?}");
    }
}

#[test]
fn recovery_dial_receipt_method_matrix_accepts_only_exact_supported_server_pairs() {
    let pairs = [
        ("RevisionService.BranchCreate", "branch.create"),
        ("RevisionService.BranchPush", "branch.push"),
        ("LockService.Lock", "lock.acquire"),
        ("LockService.Lock", "lock.renew"),
        ("LockService.Unlock", "lock.release"),
        ("LockService.ForceUnlock", "lock.force_release"),
    ];
    for (rpc, method) in pairs {
        assert!(recovery_receipt_method_matches(rpc, method));
        assert!(
            !recovery_receipt_method_matches(rpc, rpc),
            "wire RPC is not a server receipt method"
        );
        for (other_rpc, other_method) in pairs {
            assert_eq!(
                recovery_receipt_method_matches(rpc, other_method),
                rpc == other_rpc,
                "must not borrow a different operation's receipt"
            );
        }
        for wrong in [
            "",
            "branch_push",
            "branch.push.extra",
            "lock.admin_acquire",
            "repository.create",
            "Branch.Push",
        ] {
            assert!(!recovery_receipt_method_matches(rpc, wrong));
        }
    }
    for rpc in [
        "",
        "StorageService.Put",
        "LockService.AdminLock",
        "RevisionService.BranchDelete",
        "branch.push",
    ] {
        for (_, method) in pairs {
            assert!(!recovery_receipt_method_matches(rpc, method));
        }
        assert!(!recovery_receipt_method_matches(rpc, rpc));
    }
}

#[test]
fn recovery_dial_canonical_producer_endpoint_selects_real_registered_protocol() {
    for (selected, expected) in [
        ("http://LOCALHOST:46340", "grpc://localhost:46340/"),
        ("https://EXAMPLE.COM:8443", "grpcs://example.com:8443/"),
        ("http://example.com:80", "grpc://example.com:80/"),
        ("https://example.com:443", "grpcs://example.com:443/"),
        ("http://example.com", "grpc://example.com:80/"),
        ("https://example.com", "grpcs://example.com:443/"),
        ("http://[::1]:46340", "grpc://[::1]:46340/"),
    ] {
        // Run the same canonical producer used by selected_caller_namespace,
        // including URL's removal of explicit standard HTTP(S) ports.
        let recorded = canonical_endpoint(selected).expect("producer endpoint");
        let original = recorded.clone();
        let dial = recovery_dial_url(&recorded).expect("recovery dial URL");
        assert_eq!(dial, expected);
        assert_eq!(recorded, original, "persisted namespace stays unchanged");
        let old = url::Url::parse(&recorded).expect("canonical URL");
        assert!(
            lore_transport::connection::find(old.scheme()).is_err(),
            "old direct canonical URL must reproduce protocol-selection refusal"
        );
        let converted = url::Url::parse(&dial).expect("dial URL");
        assert!(lore_transport::connection::find(converted.scheme()).is_ok());
        assert_eq!(old.host_str(), converted.host_str());
        assert_eq!(old.port_or_known_default(), converted.port());
        assert_eq!(old.scheme() == "https", converted.scheme() == "grpcs");
    }
}

#[test]
fn recovery_dial_existing_grpc_urls_preserve_transport_defaults_and_authority() {
    for endpoint in [
        "grpc://localhost",
        "grpcs://example.com",
        "grpc://localhost:41337/",
        "grpcs://example.com:8443/",
        "grpcs://[::1]:443/",
    ] {
        let expected = url::Url::parse(endpoint).expect("valid transport URL");
        let dial = recovery_dial_url(endpoint).expect("existing transport URL");
        assert_eq!(dial, expected.as_str());
        let converted = url::Url::parse(&dial).expect("dial URL");
        assert_eq!(
            expected.port(),
            converted.port(),
            "do not introduce a new transport default"
        );
        assert!(lore_transport::connection::find(converted.scheme()).is_ok());
    }
}

#[test]
fn recovery_dial_rejects_ambiguous_or_unsupported_endpoint_without_retargeting() {
    for endpoint in [
        "",
        "localhost:46340",
        "http:localhost",
        "https:///",
        "http://",
        "http://host:99999",
        "ftp://host/",
        "file:///fixture",
        "mailto:host",
        "http:///host",
        "http:////host",
        "http://host/a/..",
        "http://host/%2e/",
        "http://host\\other",
        "http://\\host",
        "http://host/\\",
        "http://user@host/",
        "https://user:secret@host/",
        "http://host/?query=1",
        "https://host/#fragment",
        "grpc://host/repository",
        "https://host/nested/path",
        " http://host/",
        "http://host/ ",
        "http://host/\n",
        "http://ho\tst/",
    ] {
        assert!(
            recovery_dial_url(endpoint).is_err(),
            "must refuse {endpoint:?}"
        );
    }
}
