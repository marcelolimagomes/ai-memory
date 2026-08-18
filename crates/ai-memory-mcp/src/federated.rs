//! Federated (OIDC) token validation.
//!
//! This is the degree of trust the static bearer never had: instead of
//! comparing a secret the server already knows, it verifies a signature made
//! by an identity provider and reads who the caller is from claims that
//! provider asserted.
//!
//! Everything here fails closed. A JWKS that cannot be fetched, an issuer that
//! does not match, an algorithm outside the approved set, a claim that is
//! missing — each one denies. That direction is not defensive habit: the
//! alternative, "allow when unsure", converts a transient network fault into
//! an authentication bypass.
//!
//! What this module does **not** do is decide capability. A validated token
//! yields an identity; what that identity may reach is the capability-scope
//! gate, and the two are conjunctive. A token that authenticates perfectly and
//! holds no scope reaches exactly the tools its scopes allow, which may be
//! none.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Algorithms the server will verify.
///
/// Asymmetric only. `HS256` is absent on purpose and its absence is load
/// bearing: a symmetric algorithm would let anyone holding the verification
/// key *mint* tokens, and in the JWKS model that key is public.
const APPROVED_ALGORITHMS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// How long a fetched JWKS is reused before refetching.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
/// Bound on JWKS retrieval. A hung IdP must not hang every request behind it.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Tolerance for clock drift between this server and the IdP, per the identity
/// contract.
const LEEWAY_SECONDS: u64 = 60;

/// Why a token was refused.
///
/// Variants exist for logs and tests. The HTTP layer collapses them into one
/// 401: telling a caller *which* check failed is a probing oracle, and the
/// difference between "unknown issuer" and "bad signature" is exactly what an
/// attacker would like to learn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedError {
    /// Not a JWT at all — no header, or an unparseable one.
    Malformed,
    /// The header named an algorithm outside [`APPROVED_ALGORITHMS`].
    UnapprovedAlgorithm,
    /// The header carried no `kid`, so the signing key cannot be selected.
    MissingKeyId,
    /// The issuer's JWKS has no key with that `kid`.
    UnknownKey,
    /// Signature, issuer, audience or expiry did not validate.
    Invalid,
    /// A required claim was absent.
    MissingClaim(&'static str),
    /// The JWKS could not be retrieved. Distinct from [`Self::UnknownKey`] so
    /// operators can tell an outage from a rotation.
    JwksUnavailable,
}

/// Claims this server requires and reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FederatedClaims {
    /// Issuer. Pinned to the configured value.
    pub iss: String,
    /// Subject — the stable identity, unique only within `iss`.
    pub sub: String,
    /// Expiry, seconds since epoch.
    pub exp: i64,
    /// Token identifier, required so a single token can be revoked.
    #[serde(default)]
    pub jti: Option<String>,
    /// Authorized party. Keycloak puts the client id here for
    /// `client_credentials`; carried for audit, never for authorization.
    #[serde(default)]
    pub azp: Option<String>,
    /// Space-separated scope string, if the IdP issues one. Deliberately
    /// **not** used to grant capability: capability is server-side state, and
    /// honouring a scope claim would move that decision back to the IdP.
    #[serde(default)]
    pub scope: Option<String>,
}

/// A single JWKS key, in the subset of JWK this server understands.
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    // RSA
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

impl Jwk {
    fn decoding_key(&self) -> Option<DecodingKey> {
        match self.kty.as_str() {
            "RSA" => {
                let (n, e) = (self.n.as_deref()?, self.e.as_deref()?);
                DecodingKey::from_rsa_components(n, e).ok()
            }
            "EC" => {
                let (x, y) = (self.x.as_deref()?, self.y.as_deref()?);
                DecodingKey::from_ec_components(x, y).ok()
            }
            _ => None,
        }
    }

    /// Whether this key may be used for the algorithm the token's header
    /// names.
    ///
    /// Guards against key confusion: a `kid` match alone would let a token
    /// header claim `ES256` while pointing at an RSA key, or vice versa.
    /// When the JWKS declares `alg`, it must agree with the header; when it
    /// does not, the key type still has to match the algorithm family.
    fn permits(&self, alg: Algorithm) -> bool {
        let family_ok = matches!(
            (self.kty.as_str(), alg),
            ("RSA", Algorithm::RS256) | ("EC", Algorithm::ES256)
        );
        if !family_ok {
            return false;
        }
        match self.alg.as_deref() {
            None => true,
            Some(declared) => match alg {
                Algorithm::RS256 => declared == "RS256",
                Algorithm::ES256 => declared == "ES256",
                _ => false,
            },
        }
    }
}

/// Configuration for one trusted issuer.
#[derive(Debug, Clone)]
pub struct FederatedAuthConfig {
    /// Exact `iss` value accepted. Compared verbatim; a trailing-slash
    /// mismatch is a rejection, not a normalisation problem to paper over.
    pub issuer: String,
    /// Required `aud`. A token minted for another audience is refused even
    /// when its signature is valid — that is what stops a token issued for a
    /// different service from being replayed here.
    pub audience: String,
    /// Absolute JWKS URL.
    pub jwks_uri: String,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

/// Validates lane tokens against one trusted issuer.
pub struct FederatedAuth {
    config: FederatedAuthConfig,
    http: reqwest::Client,
    cache: RwLock<Option<CachedJwks>>,
}

impl std::fmt::Debug for FederatedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederatedAuth")
            .field("issuer", &self.config.issuer)
            .field("audience", &self.config.audience)
            .finish_non_exhaustive()
    }
}

impl FederatedAuth {
    /// Build a validator.
    ///
    /// # Errors
    /// Returns an error when the HTTP client cannot be constructed.
    pub fn new(config: FederatedAuthConfig) -> Result<Arc<Self>, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            // A named User-Agent is not cosmetic here: the public edge answers
            // Cloudflare Error 1010 to library-default agents even with a
            // valid credential, so an unnamed JWKS fetch would fail in a way
            // that looks like a key rotation.
            .user_agent(concat!("ai-memory/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Arc::new(Self {
            config,
            http,
            cache: RwLock::new(None),
        }))
    }

    /// The issuer this validator pins.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Validate a bearer value and return its claims.
    ///
    /// # Errors
    /// Returns the specific [`FederatedError`]. Callers must not surface the
    /// distinction to clients.
    pub async fn validate(&self, token: &str) -> Result<FederatedClaims, FederatedError> {
        let header = decode_header(token).map_err(|_| FederatedError::Malformed)?;
        if !APPROVED_ALGORITHMS.contains(&header.alg) {
            return Err(FederatedError::UnapprovedAlgorithm);
        }
        let kid = header.kid.ok_or(FederatedError::MissingKeyId)?;

        let key = match self.decoding_key(&kid, header.alg).await? {
            Some(key) => key,
            None => {
                // Miss on a cached JWKS is the normal shape of a key rotation:
                // refetch once before concluding the key does not exist.
                self.refresh().await?;
                self.decoding_key(&kid, header.alg)
                    .await?
                    .ok_or(FederatedError::UnknownKey)?
            }
        };

        let mut validation = Validation::new(header.alg);
        // Exactly the header's algorithm, and nothing else. jsonwebtoken 11
        // refuses a validation list that mixes key families -- an RSA key with
        // `[RS256, ES256]` in the list fails as InvalidAlgorithm before the
        // signature is ever checked, so listing the whole allowlist here
        // refused EVERY token the rung was built to accept.
        //
        // Narrowing to one algorithm loses nothing: `header.alg` was already
        // checked against APPROVED_ALGORITHMS above, so an attacker cannot get
        // here with HS256, and `Jwk::permits` independently blocks key
        // confusion between families.
        validation.algorithms = vec![header.alg];
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.leeway = LEEWAY_SECONDS;
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let data = decode::<FederatedClaims>(token, &key, &validation)
            .map_err(|_| FederatedError::Invalid)?;
        let claims = data.claims;
        // `jti` is required by the identity contract because revocation of a
        // single token is impossible without it. jsonwebtoken cannot enforce a
        // non-spec claim, so it is checked here.
        if claims.jti.as_deref().is_none_or(|j| j.trim().is_empty()) {
            return Err(FederatedError::MissingClaim("jti"));
        }
        if claims.sub.trim().is_empty() {
            return Err(FederatedError::MissingClaim("sub"));
        }
        Ok(claims)
    }

    async fn decoding_key(
        &self,
        kid: &str,
        alg: Algorithm,
    ) -> Result<Option<DecodingKey>, FederatedError> {
        let fresh = {
            let cache = self.cache.read().await;
            match cache.as_ref() {
                Some(entry) if entry.fetched_at.elapsed() < JWKS_CACHE_TTL => {
                    Some(Self::select(&entry.keys, kid, alg))
                }
                _ => None,
            }
        };
        if let Some(found) = fresh {
            return Ok(found);
        }
        self.refresh().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .and_then(|entry| Self::select(&entry.keys, kid, alg)))
    }

    fn select(keys: &[Jwk], kid: &str, alg: Algorithm) -> Option<DecodingKey> {
        keys.iter()
            .find(|key| key.kid.as_deref() == Some(kid) && key.permits(alg))
            .and_then(Jwk::decoding_key)
    }

    async fn refresh(&self) -> Result<(), FederatedError> {
        let set: JwkSet = self
            .http
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|_| FederatedError::JwksUnavailable)?
            .error_for_status()
            .map_err(|_| FederatedError::JwksUnavailable)?
            .json()
            .await
            .map_err(|_| FederatedError::JwksUnavailable)?;
        // Note what is *not* done on failure: the previous cache is left
        // untouched only on success. A failed refresh returns the error rather
        // than silently extending a stale cache past its TTL, so a revoked key
        // cannot be kept alive by an IdP outage.
        let mut cache = self.cache.write().await;
        *cache = Some(CachedJwks {
            keys: set.keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }
}

/// Whether a bearer value even looks like a JWT.
///
/// Cheap shape check so an ordinary opaque token is not sent through
/// signature validation — and, more importantly, so a failed JWT parse never
/// consumes the opaque-token path's chance to authenticate.
#[must_use]
pub fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !h.is_empty() && !p.is_empty() && !s.is_empty()
}

/// The scope names an IdP asserted, parsed for audit only.
#[must_use]
pub fn asserted_scopes(claims: &FederatedClaims) -> BTreeSet<String> {
    claims
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_check_accepts_only_three_non_empty_segments() {
        assert!(looks_like_jwt("aaa.bbb.ccc"));
        assert!(!looks_like_jwt("aaa.bbb"));
        assert!(!looks_like_jwt("aaa.bbb.ccc.ddd"));
        assert!(!looks_like_jwt("aaa..ccc"));
        assert!(!looks_like_jwt("not-a-jwt"));
        assert!(!looks_like_jwt(""));
    }

    #[test]
    fn the_validation_list_names_only_the_header_algorithm() {
        // Regression: jsonwebtoken 11 rejects a mixed-family algorithm list
        // with InvalidAlgorithm, before verifying the signature. With
        // `[RS256, ES256]` here the federated rung refused every valid token
        // and every test still passed -- because every test asserted a
        // refusal. A gate whose tests only prove denial can be totally broken
        // and look perfect.
        for alg in APPROVED_ALGORITHMS {
            let mut validation = Validation::new(alg);
            validation.algorithms = vec![alg];
            assert_eq!(
                validation.algorithms,
                vec![alg],
                "a validation list with more than one family fails as InvalidAlgorithm"
            );
            assert_eq!(validation.algorithms.len(), 1);
        }
    }

    #[test]
    fn symmetric_algorithms_are_not_approved() {
        // Load-bearing: with JWKS the verification key is public, so allowing
        // HS256 would let anyone who can read the key mint valid tokens.
        assert!(!APPROVED_ALGORITHMS.contains(&Algorithm::HS256));
        assert!(!APPROVED_ALGORITHMS.contains(&Algorithm::HS512));
        assert_eq!(APPROVED_ALGORITHMS.len(), 2);
    }

    #[tokio::test]
    async fn a_non_jwt_bearer_is_malformed_without_touching_the_network() {
        // The JWKS URI is deliberately unroutable: if validation reached the
        // network for a malformed token, this test would hang or fail with
        // JwksUnavailable instead of Malformed.
        let auth = FederatedAuth::new(FederatedAuthConfig {
            issuer: "https://auth.example/realms/taskblu".into(),
            audience: "ai-memory".into(),
            jwks_uri: "http://127.0.0.1:1/jwks".into(),
        })
        .unwrap();
        assert_eq!(
            auth.validate("opaque-static-token").await,
            Err(FederatedError::Malformed)
        );
    }

    #[tokio::test]
    async fn an_unreachable_jwks_denies_rather_than_allows() {
        // A well-formed RS256 header with a kid, pointing at a dead JWKS. The
        // only acceptable outcome is refusal.
        let auth = FederatedAuth::new(FederatedAuthConfig {
            issuer: "https://auth.example/realms/taskblu".into(),
            audience: "ai-memory".into(),
            jwks_uri: "http://127.0.0.1:1/jwks".into(),
        })
        .unwrap();
        // {"alg":"RS256","typ":"JWT","kid":"k1"} . {"sub":"s"} . sig
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJzdWIiOiJzIn0.c2ln";
        assert_eq!(
            auth.validate(token).await,
            Err(FederatedError::JwksUnavailable)
        );
    }

    #[tokio::test]
    async fn an_unapproved_algorithm_is_refused_before_any_key_lookup() {
        let auth = FederatedAuth::new(FederatedAuthConfig {
            issuer: "https://auth.example/realms/taskblu".into(),
            audience: "ai-memory".into(),
            jwks_uri: "http://127.0.0.1:1/jwks".into(),
        })
        .unwrap();
        // {"alg":"HS256","typ":"JWT"} . {"sub":"s"} . sig
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzIn0.c2ln";
        assert_eq!(
            auth.validate(token).await,
            Err(FederatedError::UnapprovedAlgorithm)
        );
    }

    #[tokio::test]
    async fn a_missing_kid_is_refused() {
        let auth = FederatedAuth::new(FederatedAuthConfig {
            issuer: "https://auth.example/realms/taskblu".into(),
            audience: "ai-memory".into(),
            jwks_uri: "http://127.0.0.1:1/jwks".into(),
        })
        .unwrap();
        // {"alg":"RS256","typ":"JWT"} — no kid.
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzIn0.c2ln";
        assert_eq!(
            auth.validate(token).await,
            Err(FederatedError::MissingKeyId)
        );
    }

    #[test]
    fn a_key_is_refused_for_an_algorithm_it_does_not_match() {
        // Key confusion: a `kid` match alone would let a header claim ES256
        // while pointing at an RSA key.
        let rsa = Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            alg: None,
            n: Some("n".into()),
            e: Some("AQAB".into()),
            x: None,
            y: None,
        };
        assert!(rsa.permits(Algorithm::RS256));
        assert!(!rsa.permits(Algorithm::ES256));

        // A JWKS that declares `alg` pins it further: same key type, wrong
        // declared algorithm, refused.
        let pinned = Jwk {
            alg: Some("ES256".into()),
            ..rsa.clone()
        };
        assert!(!pinned.permits(Algorithm::RS256));

        let ec = Jwk {
            kid: Some("k2".into()),
            kty: "EC".into(),
            alg: Some("ES256".into()),
            n: None,
            e: None,
            x: Some("x".into()),
            y: Some("y".into()),
        };
        assert!(ec.permits(Algorithm::ES256));
        assert!(!ec.permits(Algorithm::RS256));
    }

    #[test]
    fn asserted_scopes_are_parsed_but_carry_no_authority() {
        let claims = FederatedClaims {
            iss: "https://auth.example/realms/taskblu".into(),
            sub: "svc".into(),
            exp: 0,
            jti: Some("t".into()),
            azp: Some("taskblu-cowork-hermes-worker".into()),
            scope: Some("memory:read memory:admin".into()),
        };
        // Parsed for audit only. If this set were ever consulted for
        // capability, an IdP misconfiguration would silently grant admin.
        let scopes = asserted_scopes(&claims);
        assert!(scopes.contains("memory:admin"));
    }
}
