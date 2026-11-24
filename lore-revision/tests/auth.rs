// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// Note: `login_with_a_lore_token_tests` points LORE_AUTH_PATH and LORE_AUTH_STORE at a sandbox for
// this whole test binary, from a constructor. Any token-store test added here shares that store.
mod tests {
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    #[test]
    fn expiry_time_is_expired() {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        assert!(lore_transport::auth::exchange::is_expired(
            current.as_millis() as u64
        ));
    }

    #[test]
    fn one_second_in_the_future_is_not_expired() {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        assert!(!lore_transport::auth::exchange::is_expired(
            (current + Duration::from_secs(1)).as_millis() as u64
        ));
    }

    #[test]
    fn one_second_in_the_past_is_expired() {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        assert!(lore_transport::auth::exchange::is_expired(
            (current - Duration::from_secs(1)).as_millis() as u64
        ));
    }

    /// `lore auth login <remote> --token <jwt> --token-type lore --auth-url <url>` stores the
    /// token under the audience's hosts. A local deployment's tokens name `localhost`, which
    /// must stay a host so the token can be sent to the loopback server it was issued for.
    mod login_with_a_lore_token_tests {
        use std::sync::Arc;

        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use lore_base::runtime::LORE_CONTEXT;
        use lore_credential::token_store::load_all_identities;
        use lore_credential::token_store::load_user_token_from_store;
        use lore_credential::token_store::tokens_only_for_recipient_domain;
        use lore_revision::auth::login::with_token_boxed;
        use lore_revision::interface::ExecutionContext;
        use lore_revision::interface::LoreGlobalArgs;
        use lore_revision::relay::EventDispatcher;

        /// Points the token store at a directory of this process's own, in its fallback form, so
        /// no test reads or writes the developer's credentials or keyring. A constructor because
        /// the environment is process-wide and this runs before the harness starts its threads.
        #[ctor::ctor]
        fn sandbox_token_store() {
            let sandbox = lore_base::test_util::TempDir::new("lore-revision-auth-tests-");
            // Safety: constructors run before `main`, the single-threaded window in which writing
            // the environment has no reader to race.
            unsafe {
                std::env::set_var("LORE_AUTH_PATH", sandbox.path());
                std::env::set_var("LORE_AUTH_STORE", "fallback");
            }
            // The directory lives for the process; the OS temp cleaner removes it.
            Box::leak(Box::new(sandbox));
        }

        const REMOTE: &str = "lores://localhost:43810";
        const AUTH_URL: &str = "https://host.docker.internal:43838";

        fn authn_token() -> String {
            let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let claims = URL_SAFE_NO_PAD.encode(
                r#"{"iss":"commit0","sub":"login-localhost-user","exp":4102444800,"aud":["commit0-cli","host.docker.internal","localhost"]}"#,
            );
            format!("{header}.{claims}.signature")
        }

        #[tokio::test]
        async fn a_localhost_audience_token_is_stored_for_localhost() {
            let execution = Arc::new(ExecutionContext::new_client(
                LoreGlobalArgs::default(),
                EventDispatcher::new(None),
            ));
            let token = authn_token();
            let user = LORE_CONTEXT
                .scope(
                    execution,
                    with_token_boxed(REMOTE, &token, "lore", Some(AUTH_URL)),
                )
                .await
                .expect("the lore token logs in without a network");
            assert_eq!(user.id, "login-localhost-user");

            let stored = load_all_identities(false)
                .await
                .expect("the sandboxed store loads")
                .into_iter()
                .find(|stored| stored.user_id == user.id)
                .expect("the login stored an entry");
            assert!(
                stored
                    .acceptable_root_domains
                    .contains(&"localhost".to_string()),
                "domains: {:?}",
                stored.acceptable_root_domains
            );
            assert!(
                !stored
                    .acceptable_root_domains
                    .contains(&"commit0-cli".to_string())
            );

            let for_localhost = load_user_token_from_store(
                &stored.auth_url,
                &user.id,
                tokens_only_for_recipient_domain("localhost".to_string()),
            )
            .await
            .expect("the token is found for the loopback server it names");
            assert_eq!(for_localhost, token);

            load_user_token_from_store(
                &stored.auth_url,
                &user.id,
                tokens_only_for_recipient_domain("other.example".to_string()),
            )
            .await
            .expect_err("an unrelated host finds no token");
        }
    }

    mod verify_jwt_usage_for_remote_tests {

        use lore_credential::JWTUserInfo;
        use lore_credential::verify_jwt_usage_for_remote;

        fn make_jwt_with_audience(audience: Vec<String>) -> JWTUserInfo {
            JWTUserInfo {
                issuer: "my_test_issuer.example.com".to_string(),
                user_id: "my_user_id".into(),
                identity: None,
                identity_namespaced: None,
                name: Some("my_name".into()),
                preferred_username: None,
                is_service_account: None,
                expires: 1,
                audience,
                root_domains: None,
                root_domains_namespaced: None,
            }
        }

        #[test]
        fn acceptable_jwt_domains() {
            let token = make_jwt_with_audience(vec![
                "lore-1.example.com".to_string(),
                "lore-2.example.com".to_string(),
            ]);
            let acceptable_domains = token.acceptable_root_domains();

            assert_eq!(
                acceptable_domains,
                vec![
                    "lore-1.example.com".to_string(),
                    "lore-2.example.com".to_string(),
                ]
            );
        }

        #[test]
        fn errors_on_domain_not_in_audience() {
            let token = make_jwt_with_audience(vec!["real.lore.example.com".to_string()]);
            verify_jwt_usage_for_remote(&token, "attacker.lore.example.com").unwrap_err();
        }

        #[test]
        fn allows_exact_jwt_aud_use() {
            let token = make_jwt_with_audience(vec![
                "some_other_remote.example.com".to_string(),
                "lore.example.com".to_string(),
            ]);

            verify_jwt_usage_for_remote(&token, "lore.example.com").unwrap();
        }

        #[test]
        fn allows_jwt_aud_root_domain_matching_use() {
            let token = make_jwt_with_audience(vec!["lore.example.com".to_string()]);

            verify_jwt_usage_for_remote(&token, "lore-server.lore.example.com").unwrap();
        }

        #[test]
        fn leading_dot_aud_matches_subdomains_and_apex() {
            let token = make_jwt_with_audience(vec![".lore.example.com".to_string()]);

            // Subdomains ("*.lore.example.com") match.
            verify_jwt_usage_for_remote(&token, "lore-server.lore.example.com").unwrap();
            // The bare apex domain ("lore.example.com") also matches.
            verify_jwt_usage_for_remote(&token, "lore.example.com").unwrap();
        }

        #[test]
        fn leading_dot_aud_rejects_unrelated_domain() {
            let token = make_jwt_with_audience(vec![".lore.example.com".to_string()]);

            verify_jwt_usage_for_remote(&token, "attackerlore.example.com").unwrap_err();
        }

        #[test]
        fn naked_aud_rejects_mid_label_suffix_domain() {
            // A dotless `aud` must respect the label boundary.
            let token = make_jwt_with_audience(vec!["epicgames.net".to_string()]);

            // The apex and true subdomains match.
            verify_jwt_usage_for_remote(&token, "epicgames.net").unwrap();
            verify_jwt_usage_for_remote(&token, "lore.epicgames.net").unwrap();
            // The look-alike registrable domain does not.
            verify_jwt_usage_for_remote(&token, "evilepicgames.net").unwrap_err();
        }

        #[test]
        fn legacy_audience_yields_only_the_suffix() {
            let token = make_jwt_with_audience(vec!["URC".into(), ".epicgames.net".into()]);
            assert_eq!(token.acceptable_root_domains(), vec![".epicgames.net"]);
        }

        #[test]
        fn https_audience_yields_its_host() {
            let token = make_jwt_with_audience(vec!["https://lore.example.com/api".into()]);
            assert_eq!(token.acceptable_root_domains(), vec!["lore.example.com"]);
        }

        #[test]
        fn opaque_audience_fails_closed() {
            let token = make_jwt_with_audience(vec!["lore-api".into()]);
            assert!(token.acceptable_root_domains().is_empty());
            let err = verify_jwt_usage_for_remote(&token, "my_test_issuer.example.com")
                .unwrap_err()
                .to_string();
            assert!(err.contains("root_domains") && err.contains("audience"));
        }

        #[test]
        fn root_domains_claim_wins_over_audience() {
            let mut token = make_jwt_with_audience(vec!["other.example.org".into()]);
            token.root_domains = Some(vec!["lore.example.com".into()]);
            assert_eq!(token.acceptable_root_domains(), vec!["lore.example.com"]);
        }

        #[test]
        fn namespaced_alias_is_read_identically() {
            let mut token = make_jwt_with_audience(vec!["other.example.org".into()]);
            token.root_domains_namespaced = Some(vec!["lore.example.com".into()]);
            assert_eq!(token.acceptable_root_domains(), vec!["lore.example.com"]);
        }
    }
}
