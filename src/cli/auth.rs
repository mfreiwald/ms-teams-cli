use clap::Subcommand;
use std::time::Instant;

use crate::auth;
use crate::config::{self, ConfigFile};
use crate::error::{Result, TeamsError};
use crate::output::{self, OutputFormat};

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Authenticate with Microsoft Teams
    Login {
        /// Use client credentials flow (non-interactive)
        #[arg(long)]
        client_credentials: bool,

        /// Use device code flow
        #[arg(long)]
        device_code: bool,

        /// Log in with a pre-obtained access token (e.g. a Bearer token
        /// captured from an active Teams/Outlook web session). Pass the token
        /// as the value, or use `-`/omit the value to read it from stdin. The
        /// token is stored as-is and cannot be refreshed automatically.
        #[arg(
            long,
            value_name = "TOKEN",
            num_args = 0..=1,
            default_missing_value = "-",
            conflicts_with_all = ["client_credentials", "device_code"]
        )]
        token: Option<String>,

        /// Azure AD application (client) ID
        #[arg(long, env = "TEAMS_CLI_CLIENT_ID")]
        client_id: Option<String>,

        /// Azure AD client secret
        #[arg(long, env = "TEAMS_CLI_CLIENT_SECRET")]
        client_secret: Option<String>,

        /// Azure AD tenant ID
        #[arg(long, env = "TEAMS_CLI_TENANT_ID")]
        tenant_id: Option<String>,

        /// OAuth scopes (space-separated, for delegated flows)
        #[arg(long, env = "TEAMS_CLI_SCOPES")]
        scopes: Option<String>,
    },
    /// Silently redeem the stored refresh token for the resolved delegated scopes
    Refresh {
        /// OAuth scopes (space-separated, for delegated flows)
        #[arg(long, env = "TEAMS_CLI_SCOPES")]
        scopes: Option<String>,
    },
    /// Check current auth status
    Status,
    /// Print the admin consent URL for the active auth app
    ConsentUrl {
        /// Azure AD application (client) ID
        #[arg(long, env = "TEAMS_CLI_CLIENT_ID")]
        client_id: Option<String>,

        /// Azure AD tenant ID or domain
        #[arg(long, env = "TEAMS_CLI_TENANT_ID")]
        tenant_id: Option<String>,

        /// OAuth scopes (space-separated) to include in the consent URL
        #[arg(long, env = "TEAMS_CLI_SCOPES")]
        scopes: Option<String>,
    },
    /// Diagnose auth configuration and current token state
    Doctor {
        /// Azure AD application (client) ID
        #[arg(long, env = "TEAMS_CLI_CLIENT_ID")]
        client_id: Option<String>,

        /// Azure AD tenant ID or domain
        #[arg(long, env = "TEAMS_CLI_TENANT_ID")]
        tenant_id: Option<String>,
    },
    /// List all authenticated profiles
    List,
    /// Switch active profile
    Switch {
        /// Profile name to switch to
        name: String,
    },
    /// Clear stored credentials
    Logout {
        /// Logout a specific profile
        #[arg(long)]
        profile: Option<String>,
        /// Logout all profiles
        #[arg(long)]
        all: bool,
    },
    /// Export current access token
    Token {
        /// Token output format: bearer, json
        #[arg(long, default_value = "bearer")]
        format: String,
    },
}

fn token_diagnostics(claims: Option<&auth::token::TokenClaims>) -> Option<serde_json::Value> {
    claims.map(|claims| {
        serde_json::json!({
            "audience": claims.audience(),
            "is_graph_audience": claims.is_graph_audience(),
            "auth_type": claims.auth_type(),
            "tenant_id": claims.tid,
            "app_id": claims.appid.clone().or_else(|| claims.azp.clone()),
            "user": claims.preferred_username.clone().or_else(|| claims.upn.clone()),
        })
    })
}

fn token_warnings(claims: Option<&auth::token::TokenClaims>) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(claims) = claims {
        if claims.is_graph_audience() == Some(false) {
            let audience = claims
                .audience()
                .unwrap_or_else(|| "unknown audience".into());
            warnings.push(format!(
                "Token audience is '{audience}', not Microsoft Graph. Graph commands require a Microsoft Graph access token."
            ));
        }
    }

    warnings
}

fn graph_admin_consent_scopes(scopes: &str) -> String {
    scopes
        .split_whitespace()
        .map(|scope| {
            if scope.starts_with("https://")
                || matches!(scope, "openid" | "profile" | "email" | "offline_access")
            {
                scope.to_string()
            } else {
                format!("https://graph.microsoft.com/{scope}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Turn the identity platform's consent-required rejection (AADSTS65001) of a
/// refresh-token redemption into actionable guidance. The platform rejects the
/// whole request when any requested scope lacks consent; it never returns a
/// narrower token. When an explicit scope override failed, the guidance names
/// it so the consent URL covers the exact scope set that was rejected.
fn annotate_consent_error(
    error: TeamsError,
    profile: &str,
    requested_scopes: Option<&str>,
) -> TeamsError {
    match error {
        TeamsError::AuthError(message)
            if message.contains("AADSTS65001") || message.contains("consent_required") =>
        {
            let consent_command = match requested_scopes {
                Some(scopes) => {
                    format!("teams --profile {profile} auth consent-url --scopes \"{scopes}\"")
                }
                None => format!("teams --profile {profile} auth consent-url"),
            };
            TeamsError::AuthError(format!(
                "{message}\n\nThe requested scopes have not been consented for this app. \
                 Grant admin consent (run `{consent_command}` for the URL) and retry, or run \
                 `teams --profile {profile} auth login` for interactive consent."
            ))
        }
        other => other,
    }
}

fn delegated_admin_consent_url(client_id: &str, tenant_id: &str, delegated_scopes: &str) -> String {
    let scopes = graph_admin_consent_scopes(delegated_scopes);
    format!(
        "https://login.microsoftonline.com/{tenant_id}/v2.0/adminconsent?client_id={client_id}&scope={}&redirect_uri={}",
        urlencoding::encode(&scopes),
        urlencoding::encode(config::DEFAULT_REDIRECT_URI)
    )
}

/// Read the access token supplied to `auth login --token`. A value of `-`
/// (also the default when the flag is passed without a value) reads the token
/// from stdin, so it never lands in shell history or the process table. Any
/// surrounding whitespace and an accidental `Bearer ` prefix are stripped.
fn read_provided_token(arg: &str) -> Result<String> {
    let raw = if arg == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| {
            TeamsError::InvalidInput(format!("Failed to read token from stdin: {e}"))
        })?;
        buf
    } else {
        arg.to_string()
    };

    let trimmed = raw.trim();
    let trimmed = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .unwrap_or(trimmed)
        .trim();

    if trimmed.is_empty() {
        return Err(TeamsError::InvalidInput(
            "No token provided. Pass it as `--token <TOKEN>` or pipe it via stdin.".into(),
        ));
    }

    Ok(trimmed.to_string())
}

/// Build a `TokenInfo` from a raw access token captured outside the CLI (e.g.
/// from a browser session). The JWT is decoded unverified to recover the
/// expiry (`exp`) and granted scopes (`scp`); a value that is not a decodable
/// JWT is rejected as invalid input. No refresh token is available, so the
/// stored token cannot be silently refreshed once it expires.
fn provided_token_info(profile: &str, access_token: String) -> Result<auth::token::TokenInfo> {
    let claims = auth::token::decode_unverified_claims(&access_token).map_err(|e| {
        TeamsError::InvalidInput(format!(
            "Provided value is not a valid JWT access token ({e}). Paste the raw Bearer token from your Teams/Outlook session."
        ))
    })?;

    let expires_at = claims
        .exp
        .and_then(|exp| chrono::DateTime::from_timestamp(exp, 0));
    let scope = claims
        .scp
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(auth::token::TokenInfo {
        access_token,
        expires_at,
        token_type: "Bearer".to_string(),
        scope,
        refresh_token: None,
        profile: profile.to_string(),
    })
}

/// Warnings specific to a token supplied via `auth login --token`: it may not
/// target Microsoft Graph, it may already be expired, and it can never be
/// auto-refreshed since there is no refresh token to redeem.
fn provided_token_warnings(
    token: &auth::token::TokenInfo,
    claims: Option<&auth::token::TokenClaims>,
) -> Vec<String> {
    let mut warnings = token_warnings(claims);

    match token.expires_at {
        Some(_) if token.is_expired() => warnings.push(
            "Token is already expired. Capture a fresh token and run `teams auth login --token` again.".into(),
        ),
        None => warnings.push(
            "Token has no 'exp' claim, so its expiry is unknown; commands will keep using it until Graph rejects it.".into(),
        ),
        _ => {}
    }

    warnings.push(
        "Provided tokens have no refresh token and cannot be refreshed automatically; re-run `teams auth login --token` when it expires.".into(),
    );

    warnings
}

pub async fn run(
    cmd: AuthCommand,
    config: &ConfigFile,
    profile: &str,
    format: OutputFormat,
) -> Result<()> {
    match cmd {
        AuthCommand::Login {
            client_credentials,
            device_code,
            token,
            client_id,
            client_secret,
            tenant_id,
            scopes,
        } => {
            let start = Instant::now();

            if let Some(token_arg) = token {
                let access_token = read_provided_token(&token_arg)?;
                let token_info = provided_token_info(profile, access_token)?;

                // Store in keyring so subsequent commands reuse it, just like a
                // normal login. There is no refresh token, so it will need to be
                // re-supplied when it expires.
                auth::keyring::store_token(profile, &token_info)?;
                auth::keyring::add_profile_to_index(profile)?;

                let claims = token_info.unverified_claims();
                let msg = serde_json::json!({
                    "message": "Authenticated successfully with provided token",
                    "profile": profile,
                    "expires_at": token_info.expires_at.map(|e| e.to_rfc3339()),
                    "scope": token_info.scope,
                    "auto_refresh": false,
                    "token_diagnostics": token_diagnostics(claims.as_ref()),
                    "warnings": provided_token_warnings(&token_info, claims.as_ref()),
                });
                output::print_success(format, &msg, start);
                return Ok(());
            }

            let token_response = if client_credentials {
                let client_id = config::resolve_client_id(client_id.as_deref(), profile, config)
                    .ok_or_else(|| {
                        TeamsError::InvalidInput(
                            "Client ID is required for client credentials flow. Use --client-id or set TEAMS_CLI_CLIENT_ID".into(),
                        )
                    })?;
                let tenant_id = config::resolve_tenant_id(tenant_id.as_deref(), profile, config)
                    .ok_or_else(|| {
                        TeamsError::InvalidInput(
                            "Tenant ID is required for client credentials flow. Use --tenant-id or set TEAMS_CLI_TENANT_ID".into(),
                        )
                    })?;
                let client_secret = config::resolve_client_secret(client_secret.as_deref())
                    .ok_or_else(|| {
                        TeamsError::InvalidInput(
                            "Client secret is required for client credentials flow. Use --client-secret or set TEAMS_CLI_CLIENT_SECRET".into(),
                        )
                    })?;

                auth::client_credentials::authenticate(&client_id, &client_secret, &tenant_id)
                    .await?
            } else if device_code {
                let client_id =
                    config::resolve_delegated_client_id(client_id.as_deref(), profile, config)?;
                let tenant_id =
                    config::resolve_delegated_tenant_id(tenant_id.as_deref(), profile, config);
                let scopes = config::resolve_delegated_scopes(scopes.as_deref(), profile, config);
                auth::device_code::authenticate(&client_id, &tenant_id, Some(&scopes)).await?
            } else {
                // Default: auth code + PKCE
                let client_id =
                    config::resolve_delegated_client_id(client_id.as_deref(), profile, config)?;
                let tenant_id =
                    config::resolve_delegated_tenant_id(tenant_id.as_deref(), profile, config);
                let scopes = config::resolve_delegated_scopes(scopes.as_deref(), profile, config);
                auth::auth_code_pkce::authenticate(&client_id, &tenant_id, Some(&scopes)).await?
            };

            let token_info = token_response.into_token_info(profile);

            // Store in keyring
            auth::keyring::store_token(profile, &token_info)?;
            auth::keyring::add_profile_to_index(profile)?;

            let msg = serde_json::json!({
                "message": "Authenticated successfully",
                "profile": profile,
                "expires_at": token_info.expires_at.map(|e| e.to_rfc3339()),
                "scope": token_info.scope,
            });
            output::print_success(format, &msg, start);
            Ok(())
        }

        AuthCommand::Refresh { scopes } => {
            let start = Instant::now();
            // No explicit override means the stored token's scope is reused,
            // so a plain refresh never down-scopes a previously broader login.
            let override_scopes =
                config::resolve_delegated_scopes_override(scopes.as_deref(), profile, config);

            let (token_info, requested_scope) =
                auth::refresh_token_with_scopes(profile, override_scopes.as_deref())
                    .await
                    .map_err(|e| annotate_consent_error(e, profile, override_scopes.as_deref()))?;

            let msg = serde_json::json!({
                "message": "Token refreshed successfully",
                "profile": profile,
                "requested_scope": requested_scope,
                "granted_scope": token_info.scope,
                "expires_at": token_info.expires_at.map(|e| e.to_rfc3339()),
            });
            output::print_success(format, &msg, start);
            Ok(())
        }

        AuthCommand::ConsentUrl {
            client_id,
            tenant_id,
            scopes,
        } => {
            let start = Instant::now();
            let client_id =
                config::resolve_delegated_client_id(client_id.as_deref(), profile, config)?;
            let tenant_id =
                config::resolve_delegated_tenant_id(tenant_id.as_deref(), profile, config);
            let scopes = config::resolve_delegated_scopes(scopes.as_deref(), profile, config);
            let url = delegated_admin_consent_url(&client_id, &tenant_id, &scopes);
            let msg = serde_json::json!({
                "admin_consent_url": url,
                "client_id": client_id,
                "tenant_id": tenant_id,
                "scope": scopes,
                "redirect_uri": config::DEFAULT_REDIRECT_URI,
            });
            output::print_success(format, &msg, start);
            Ok(())
        }

        AuthCommand::Doctor {
            client_id,
            tenant_id,
        } => {
            let start = Instant::now();
            let client_id =
                config::resolve_delegated_client_id(client_id.as_deref(), profile, config)?;
            let tenant_id =
                config::resolve_delegated_tenant_id(tenant_id.as_deref(), profile, config);
            let auth_app = if client_id == config::OSO_PUBLIC_CLIENT_ID {
                "oso"
            } else {
                "byo"
            };

            let token = auth::resolve_token(profile).await.ok();
            let claims = token.as_ref().and_then(|t| t.unverified_claims());
            let warnings = token_warnings(claims.as_ref());
            let resolved_scopes = config::resolve_delegated_scopes(None, profile, config);
            let admin_consent_url =
                delegated_admin_consent_url(&client_id, &tenant_id, &resolved_scopes);
            let msg = serde_json::json!({
                "profile": profile,
                "auth_app": auth_app,
                "client_id": client_id,
                "tenant_id": tenant_id,
                "admin_consent_url": admin_consent_url,
                "default_delegated_scopes": config::DEFAULT_DELEGATED_SCOPES,
                "resolved_delegated_scopes": resolved_scopes,
                "redirect_uri": config::DEFAULT_REDIRECT_URI,
                "authenticated": token.is_some(),
                "warnings": warnings,
                "token": token.as_ref().map(|t| serde_json::json!({
                    "expires_at": t.expires_at.map(|e| e.to_rfc3339()),
                    "scope": t.scope,
                    "auth_type": claims.as_ref().map(|c| c.auth_type()).unwrap_or("unknown"),
                    "audience": claims.as_ref().and_then(|c| c.audience()),
                    "is_graph_audience": claims.as_ref().and_then(|c| c.is_graph_audience()),
                    "tenant_id": claims.as_ref().and_then(|c| c.tid.clone()),
                    "app_id": claims.as_ref().and_then(|c| c.appid.clone()).or_else(|| claims.as_ref().and_then(|c| c.azp.clone())),
                    "user": claims.as_ref().and_then(|c| c.preferred_username.clone()).or_else(|| claims.as_ref().and_then(|c| c.upn.clone())),
                })),
            });
            output::print_success(format, &msg, start);
            Ok(())
        }

        AuthCommand::Status => {
            let start = Instant::now();
            match auth::resolve_token(profile).await {
                Ok(token) => {
                    let claims = token.unverified_claims();
                    let msg = serde_json::json!({
                        "authenticated": true,
                        "profile": profile,
                        "expires_at": token.expires_at.map(|e| e.to_rfc3339()),
                        "scope": token.scope,
                        "token_diagnostics": token_diagnostics(claims.as_ref()),
                        "warnings": token_warnings(claims.as_ref()),
                    });
                    output::print_success(format, &msg, start);
                    Ok(())
                }
                Err(_) => {
                    let msg = serde_json::json!({
                        "authenticated": false,
                        "profile": profile,
                    });
                    output::print_success(format, &msg, start);
                    std::process::exit(1);
                }
            }
        }

        AuthCommand::List => {
            let start = Instant::now();
            let profiles = auth::keyring::list_profiles();
            let msg = serde_json::json!({
                "profiles": profiles,
                "active": profile,
            });
            output::print_success(format, &msg, start);
            Ok(())
        }

        AuthCommand::Switch { name } => {
            let start = Instant::now();
            // Verify the profile has a token
            auth::resolve_token(&name).await?;

            // Update config to set default profile
            let mut updated_config = config.clone();
            updated_config.default.profile = Some(name.clone());
            if let Err(e) = config::save_config(&updated_config, None) {
                tracing::warn!("Could not save profile switch to config: {e}");
            }

            let msg = serde_json::json!({
                "message": format!("Switched to profile '{name}'"),
                "profile": name,
            });
            output::print_success(format, &msg, start);
            Ok(())
        }

        AuthCommand::Logout {
            profile: target,
            all,
        } => {
            let start = Instant::now();
            if all {
                let profiles = auth::keyring::list_profiles();
                for p in &profiles {
                    auth::keyring::delete_token(p)?;
                    auth::keyring::remove_profile_from_index(p)?;
                }
                let msg = serde_json::json!({
                    "message": format!("Logged out from {} profile(s)", profiles.len()),
                });
                output::print_success(format, &msg, start);
            } else {
                let target = target.as_deref().unwrap_or(profile);
                auth::keyring::delete_token(target)?;
                auth::keyring::remove_profile_from_index(target)?;
                let msg = serde_json::json!({
                    "message": format!("Logged out from profile '{target}'"),
                });
                output::print_success(format, &msg, start);
            }
            Ok(())
        }

        AuthCommand::Token {
            format: token_format,
        } => {
            let token = auth::resolve_token(profile).await?;
            match token_format.as_str() {
                "json" => {
                    let claims = token.unverified_claims();
                    let msg = serde_json::json!({
                        "access_token": token.access_token,
                        "token_type": token.token_type,
                        "expires_at": token.expires_at.map(|e| e.to_rfc3339()),
                        "token_diagnostics": token_diagnostics(claims.as_ref()),
                    });
                    let start = Instant::now();
                    output::print_success(format, &msg, start);
                }
                _ => {
                    // bearer (default) — just print the token
                    println!("{}", token.access_token);
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn jwt_with(payload: serde_json::Value) -> String {
        format!("header.{}.sig", URL_SAFE_NO_PAD.encode(payload.to_string()))
    }

    #[test]
    fn read_provided_token_strips_bearer_prefix_and_whitespace() {
        assert_eq!(
            read_provided_token("  Bearer abc.def.ghi  ").unwrap(),
            "abc.def.ghi"
        );
        assert_eq!(read_provided_token("abc.def.ghi").unwrap(), "abc.def.ghi");
    }

    #[test]
    fn read_provided_token_rejects_empty() {
        assert!(matches!(
            read_provided_token("   "),
            Err(TeamsError::InvalidInput(_))
        ));
        assert!(matches!(
            read_provided_token(""),
            Err(TeamsError::InvalidInput(_))
        ));
    }

    #[test]
    fn provided_token_info_extracts_expiry_and_scope() {
        let token = jwt_with(serde_json::json!({
            "aud": "https://graph.microsoft.com",
            "tid": "tenant-1",
            "scp": "User.Read Chat.ReadWrite",
            "exp": 4_102_444_800_i64, // 2100-01-01
        }));

        let info = provided_token_info("work", token.clone()).unwrap();

        assert_eq!(info.access_token, token);
        assert_eq!(info.profile, "work");
        assert_eq!(info.token_type, "Bearer");
        assert!(info.refresh_token.is_none());
        assert_eq!(info.scope.as_deref(), Some("User.Read Chat.ReadWrite"));
        assert!(info.expires_at.is_some());
        assert!(!info.is_expired());
    }

    #[test]
    fn provided_token_info_rejects_non_jwt() {
        let err = provided_token_info("work", "not-a-jwt".into()).unwrap_err();
        assert!(matches!(err, TeamsError::InvalidInput(_)));
    }

    #[test]
    fn provided_token_warnings_flag_expired_and_no_refresh() {
        let token = jwt_with(serde_json::json!({
            "aud": "https://graph.microsoft.com",
            "scp": "User.Read",
            "exp": 1_000_i64, // long past
        }));
        let info = provided_token_info("work", token).unwrap();
        let claims = info.unverified_claims();

        let warnings = provided_token_warnings(&info, claims.as_ref());

        assert!(warnings.iter().any(|w| w.contains("already expired")));
        assert!(warnings.iter().any(|w| w.contains("cannot be refreshed")));
    }

    #[test]
    fn provided_token_warnings_flag_non_graph_audience() {
        let token = jwt_with(serde_json::json!({
            "aud": "https://outlook.office.com",
            "scp": "User.Read",
            "exp": 4_102_444_800_i64,
        }));
        let info = provided_token_info("work", token).unwrap();
        let claims = info.unverified_claims();

        let warnings = provided_token_warnings(&info, claims.as_ref());

        assert!(warnings.iter().any(|w| w.contains("not Microsoft Graph")));
    }

    #[test]
    fn annotate_consent_error_adds_guidance_with_requested_scopes() {
        let error = TeamsError::AuthError("Token refresh failed: AADSTS65001: no consent".into());
        let annotated = annotate_consent_error(error, "work", Some("User.Read People.Read"));

        let TeamsError::AuthError(message) = annotated else {
            panic!("expected AuthError");
        };
        assert!(message.contains("AADSTS65001"));
        assert!(message
            .contains("teams --profile work auth consent-url --scopes \"User.Read People.Read\""));
        assert!(message.contains("--profile work auth login"));
    }

    #[test]
    fn annotate_consent_error_omits_scopes_flag_without_override() {
        let error = TeamsError::AuthError("consent_required".into());
        let annotated = annotate_consent_error(error, "default", None);

        let TeamsError::AuthError(message) = annotated else {
            panic!("expected AuthError");
        };
        assert!(message.contains("`teams --profile default auth consent-url`"));
        assert!(!message.contains("--scopes"));
    }

    #[test]
    fn annotate_consent_error_passes_through_other_errors() {
        let error = TeamsError::AuthError("Token refresh failed: AADSTS70008 expired".into());
        let annotated = annotate_consent_error(error, "default", None);

        let TeamsError::AuthError(message) = annotated else {
            panic!("expected AuthError");
        };
        assert!(!message.contains("consent-url"));
    }
}
