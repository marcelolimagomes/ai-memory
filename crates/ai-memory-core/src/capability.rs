//! Capability scopes granted to an identity.
//!
//! A scope names *what an identity may do*, independently of which project the
//! data belongs to. It is the missing half of the authorization story: the
//! project ACL in `ai-memory-store::access` answers "may this user touch this
//! project?", while a capability scope answers "may this user perform this
//! class of operation at all?".
//!
//! The distinction matters because tool governance was previously imposed on
//! the *client*. A client-side allowlist is a reduction of surface, not a
//! control: an agent runtime that offers no per-server allowlist simply sees
//! every tool the server publishes. Scopes move that decision to the server,
//! where it cannot be bypassed by pointing a different client at the same
//! credential.
//!
//! Scopes are deliberately coarse. They describe capability classes, not
//! individual tool names, so adding a tool to the server does not silently
//! widen an already-granted credential — the new tool has to be mapped to an
//! existing class on purpose.

use std::collections::BTreeSet;
use std::fmt;

/// A capability class that may be granted to an identity.
///
/// The wire form is stable and is what lands in the database and in operator
/// commands. Parsing is strict: an unknown scope is an error rather than a
/// silently ignored grant, because silently dropping a scope during a grant
/// would produce a credential that is weaker than the operator believes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityScope {
    /// Discover and read memory: status, briefing, query, page reads.
    MemoryRead,
    /// Accept a handoff that was addressed to this identity.
    MemoryHandoffAccept,
    /// Create or revise memory content.
    MemoryWrite,
    /// Curate, approve, consolidate or sweep governed content.
    MemoryCurate,
    /// Operate the server: membership changes and other admin surfaces.
    MemoryAdmin,
}

impl CapabilityScope {
    /// Every scope, in escalation order. Used by operator tooling to present
    /// the full vocabulary without duplicating the list.
    pub const ALL: [Self; 5] = [
        Self::MemoryRead,
        Self::MemoryHandoffAccept,
        Self::MemoryWrite,
        Self::MemoryCurate,
        Self::MemoryAdmin,
    ];

    /// Stable wire/database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryRead => "memory:read",
            Self::MemoryHandoffAccept => "memory:handoff.accept",
            Self::MemoryWrite => "memory:write",
            Self::MemoryCurate => "memory:curate",
            Self::MemoryAdmin => "memory:admin",
        }
    }

    /// Parse the stable wire representation.
    ///
    /// Case and surrounding whitespace are forgiving because these values are
    /// typed by operators; the scope vocabulary itself is not.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "memory:read" => Some(Self::MemoryRead),
            "memory:handoff.accept" => Some(Self::MemoryHandoffAccept),
            "memory:write" => Some(Self::MemoryWrite),
            "memory:curate" => Some(Self::MemoryCurate),
            "memory:admin" => Some(Self::MemoryAdmin),
            _ => None,
        }
    }

    /// Parse a comma- or whitespace-separated scope list.
    ///
    /// Returns the offending token on the first unknown scope. Partial success
    /// is not offered on purpose: a grant that silently dropped one scope would
    /// leave the operator believing a credential is broader than it is.
    pub fn parse_set(value: &str) -> Result<BTreeSet<Self>, String> {
        let mut parsed = BTreeSet::new();
        for token in value
            .split([',', ' ', '\t', '\n'])
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            match Self::parse(token) {
                Some(scope) => {
                    parsed.insert(scope);
                }
                None => return Err(token.to_string()),
            }
        }
        Ok(parsed)
    }

    /// Render a scope set back to the canonical space-separated wire form.
    #[must_use]
    pub fn render_set(scopes: &BTreeSet<Self>) -> String {
        scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Display for CapabilityScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_round_trips() {
        for scope in CapabilityScope::ALL {
            assert_eq!(CapabilityScope::parse(scope.as_str()), Some(scope));
        }
    }

    #[test]
    fn unknown_scope_is_rejected_rather_than_ignored() {
        assert_eq!(CapabilityScope::parse("memory:everything"), None);
        // A set containing one bad token fails as a whole and names the token,
        // so an operator cannot end up with a silently narrower credential.
        let error = CapabilityScope::parse_set("memory:read, memory:root").unwrap_err();
        assert_eq!(error, "memory:root");
    }

    #[test]
    fn set_parsing_accepts_commas_and_whitespace() {
        let expected = BTreeSet::from([
            CapabilityScope::MemoryRead,
            CapabilityScope::MemoryHandoffAccept,
        ]);
        assert_eq!(
            CapabilityScope::parse_set("memory:read,memory:handoff.accept").unwrap(),
            expected
        );
        assert_eq!(
            CapabilityScope::parse_set("  memory:read   memory:handoff.accept  ").unwrap(),
            expected
        );
    }

    #[test]
    fn empty_input_is_an_empty_set_not_an_error() {
        // Distinguishing "no scopes requested" from "invalid scope" keeps the
        // caller free to treat the empty case as its own policy decision.
        assert!(CapabilityScope::parse_set("   ").unwrap().is_empty());
    }

    #[test]
    fn rendering_is_canonical_and_ordered() {
        let scopes = BTreeSet::from([CapabilityScope::MemoryWrite, CapabilityScope::MemoryRead]);
        assert_eq!(
            CapabilityScope::render_set(&scopes),
            "memory:read memory:write"
        );
    }
}
