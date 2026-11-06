// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;

use lore_server::telemetry::resource::*;
use opentelemetry::Key;
use opentelemetry::Value;
use tokio::runtime::Handle;
#[tokio::test(flavor = "multi_thread")]
async fn base_resource_labels() {
    temp_env::with_vars([("PLATFORM_INSTANCE_ID", Some("i-mine"))], || {
        let resource = resource(&None, Handle::current(), None);

        assert_eq!(
            resource.get(&Key::from_static_str("instance")),
            Some(Value::from("i-mine"))
        );
    });
}

#[test]
fn parse_replica_accepts_one_through_eight() {
    for digit in 1..=8 {
        let value = digit.to_string();
        assert_eq!(parse_replica(&value), Some(value));
    }
}

#[test]
fn parse_replica_rejects_everything_else() {
    // "\u{0662}" is ARABIC-INDIC DIGIT TWO; "\u{ff12}" is FULLWIDTH DIGIT TWO.
    for value in [
        "0", "9", "10", "01", " 1", "1 ", "a", "", "\u{0662}", "\u{ff12}", "1\n",
    ] {
        assert_eq!(parse_replica(value), None, "value {value:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_carries_replica_attribute() {
    temp_env::with_vars([(REPLICA_ENV, Some("2"))], || {
        let resource = resource(&None, Handle::current(), None);

        assert_eq!(
            resource.get(&Key::from_static_str(REPLICA_ATTRIBUTE)),
            Some(Value::from("2"))
        );
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_omits_replica_attribute_when_unset() {
    temp_env::with_vars([(REPLICA_ENV, None::<&str>)], || {
        let resource = resource(&None, Handle::current(), None);

        assert_eq!(resource.get(&Key::from_static_str(REPLICA_ATTRIBUTE)), None);
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn resource_omits_replica_attribute_when_invalid() {
    temp_env::with_vars([(REPLICA_ENV, Some("9"))], || {
        let resource = resource(&None, Handle::current(), None);

        assert_eq!(resource.get(&Key::from_static_str(REPLICA_ATTRIBUTE)), None);
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resource_with_additional_labels() {
    let labels = Some(HashMap::from([(
        "some-key".to_owned(),
        "some-value".to_owned(),
    )]));
    let resource = resource(&labels, Handle::current(), None);

    let mut found = false;
    for (k, v) in resource.iter() {
        if k.as_str() == "some-key" {
            assert_eq!(v.as_str(), "some-value");
            found = true;
        }
    }

    assert!(found);
}
