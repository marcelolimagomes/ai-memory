//! Server-side translation of capability scopes into a permitted tool surface.
//!
//! This is the module that turns a scope from a label into a control.
//!
//! Before it existed, which tools a lane could reach was decided by the client:
//! the Hermes orchestrator profile carried a four-tool allowlist, so its model
//! saw four tools, while the worker lane — which inherits its MCP registration
//! from the agent runtime's own config and has no per-server allowlist — saw
//! all of them. Same server, same credential, different surface, decided
//! entirely outside the server. Measured, not theorised: `memory_recent`
//! answered `TOOL_ABSENT` under one profile and `TOOL_AVAILABLE` under the
//! other.
//!
//! The mapping is explicit rather than derived from a naming convention. A
//! convention like "any tool starting with `memory_read`" would silently admit
//! the next tool someone names that way; an explicit table forces whoever adds
//! a tool to decide which capability class it belongs to. Tools not named here
//! are treated as [`ToolClass::Admin`] — the most restrictive class — so an
//! unmapped new tool fails closed instead of leaking into read credentials.

use std::collections::BTreeSet;

use ai_memory_core::CapabilityScope;

/// The capability class a tool belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClass {
    /// Discovery and retrieval.
    Read,
    /// Accepting a handoff addressed to this identity.
    HandoffAccept,
    /// Creating or revising content.
    Write,
    /// Curation, approval, consolidation, sweeps.
    Curate,
    /// Server operation. Also the fail-closed default for unmapped tools.
    Admin,
}

impl ToolClass {
    /// The scope that grants this class.
    #[must_use]
    pub const fn required_scope(self) -> CapabilityScope {
        match self {
            Self::Read => CapabilityScope::MemoryRead,
            Self::HandoffAccept => CapabilityScope::MemoryHandoffAccept,
            Self::Write => CapabilityScope::MemoryWrite,
            Self::Curate => CapabilityScope::MemoryCurate,
            Self::Admin => CapabilityScope::MemoryAdmin,
        }
    }

    /// The wire name of the scope that grants this class, for operator-facing
    /// denial messages.
    #[must_use]
    pub const fn required_scope_str(self) -> &'static str {
        self.required_scope().as_str()
    }
}

/// Classify one tool by name.
///
/// The unmapped default is [`ToolClass::Admin`]: a tool nobody classified is
/// reachable only by a credential holding the highest scope. That is the safe
/// direction — a new tool that should have been readable is a visible bug
/// report, while a new tool that silently became readable is a silent
/// privilege escalation.
#[must_use]
pub fn classify_tool(name: &str) -> ToolClass {
    match name {
        // Read-first surface: the four tools the orchestrator lane was
        // allowed to see client-side, plus the read-only siblings that were
        // always reachable when no client allowlist was in force.
        "memory_status" | "memory_briefing" | "memory_query" | "memory_read_page"
        | "memory_recent" | "memory_explore" => ToolClass::Read,

        // Handoff acceptance is its own class: the orchestrator needs it and
        // the worker does not, which is exactly the distinction that a single
        // `memory:read` scope for both lanes would have erased.
        "memory_handoff_accept" => ToolClass::HandoffAccept,

        "memory_write_page"
        | "memory_feedback"
        | "memory_handoff_begin"
        | "memory_handoff_cancel" => ToolClass::Write,

        "memory_delete_page"
        | "memory_consolidate"
        | "memory_lint"
        | "memory_forget_sweep"
        | "memory_auto_improve" => ToolClass::Curate,

        "memory_project_membership_set" | "memory_install_self_routing" => ToolClass::Admin,

        _ => ToolClass::Admin,
    }
}

/// The tool surface an identity may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolSurface {
    /// No scope gate applies. Either the feature is disabled, the caller is a
    /// root/local compatibility principal, or the identity has no scope rows
    /// and is therefore unscoped.
    Unrestricted,
    /// Only tools whose class is covered by these scopes are reachable.
    Scoped(BTreeSet<CapabilityScope>),
}

impl ToolSurface {
    /// Build a surface from an identity's granted scopes.
    ///
    /// An empty scope set yields [`ToolSurface::Unrestricted`], which keeps the
    /// gate opt-in per credential: existing identities keep working until an
    /// operator grants them a first scope. That is the same promotion
    /// discipline the rest of the product uses — a capability arrives disabled
    /// and is switched on deliberately.
    #[must_use]
    pub fn from_scopes(scopes: BTreeSet<CapabilityScope>) -> Self {
        if scopes.is_empty() {
            Self::Unrestricted
        } else {
            Self::Scoped(scopes)
        }
    }

    /// Whether this surface is actually enforcing anything.
    #[must_use]
    pub const fn is_enforcing(&self) -> bool {
        matches!(self, Self::Scoped(_))
    }

    /// Whether the named tool may be listed and invoked.
    ///
    /// `memory:admin` deliberately implies every other class: an operator
    /// credential that can change memberships can already reach the data by
    /// other means, so withholding read from it would be theatre rather than
    /// containment. No other scope implies another — `memory:write` does not
    /// grant read, because a lane that should only write telemetry has no
    /// business enumerating the wiki.
    #[must_use]
    pub fn allows(&self, tool_name: &str) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Scoped(scopes) => {
                if scopes.contains(&CapabilityScope::MemoryAdmin) {
                    return true;
                }
                scopes.contains(&classify_tool(tool_name).required_scope())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_only() -> ToolSurface {
        ToolSurface::from_scopes(BTreeSet::from([CapabilityScope::MemoryRead]))
    }

    #[test]
    fn empty_scope_set_does_not_enforce() {
        let surface = ToolSurface::from_scopes(BTreeSet::new());
        assert_eq!(surface, ToolSurface::Unrestricted);
        assert!(!surface.is_enforcing());
        assert!(surface.allows("memory_delete_page"));
    }

    #[test]
    fn read_scope_reaches_read_tools_only() {
        let surface = read_only();
        assert!(surface.is_enforcing());
        for tool in [
            "memory_status",
            "memory_briefing",
            "memory_query",
            "memory_read_page",
        ] {
            assert!(surface.allows(tool), "{tool} should be readable");
        }
        for tool in [
            "memory_write_page",
            "memory_delete_page",
            "memory_handoff_accept",
            "memory_project_membership_set",
        ] {
            assert!(!surface.allows(tool), "{tool} must be denied");
        }
    }

    #[test]
    fn handoff_accept_is_separable_from_read() {
        // This is the orchestrator/worker distinction. Granting both lanes a
        // single `memory:read` would have collapsed it.
        let orchestrator = ToolSurface::from_scopes(BTreeSet::from([
            CapabilityScope::MemoryRead,
            CapabilityScope::MemoryHandoffAccept,
        ]));
        let worker = read_only();
        assert!(orchestrator.allows("memory_handoff_accept"));
        assert!(!worker.allows("memory_handoff_accept"));
        // Both still read.
        assert!(orchestrator.allows("memory_query"));
        assert!(worker.allows("memory_query"));
    }

    #[test]
    fn write_does_not_imply_read() {
        let surface = ToolSurface::from_scopes(BTreeSet::from([CapabilityScope::MemoryWrite]));
        assert!(surface.allows("memory_write_page"));
        assert!(!surface.allows("memory_query"));
    }

    #[test]
    fn admin_implies_every_class() {
        let surface = ToolSurface::from_scopes(BTreeSet::from([CapabilityScope::MemoryAdmin]));
        for tool in [
            "memory_query",
            "memory_write_page",
            "memory_delete_page",
            "memory_handoff_accept",
            "memory_project_membership_set",
        ] {
            assert!(surface.allows(tool), "{tool} should be reachable by admin");
        }
    }

    #[test]
    fn unmapped_tool_fails_closed() {
        // A tool added tomorrow and forgotten here must not land in a read
        // credential's surface.
        assert_eq!(classify_tool("memory_something_new"), ToolClass::Admin);
        assert!(!read_only().allows("memory_something_new"));
    }

    #[test]
    fn every_class_has_a_distinct_required_scope() {
        // Guards against a copy-paste that maps two classes to one scope,
        // which would silently merge two capability tiers.
        let scopes: BTreeSet<_> = [
            ToolClass::Read,
            ToolClass::HandoffAccept,
            ToolClass::Write,
            ToolClass::Curate,
            ToolClass::Admin,
        ]
        .into_iter()
        .map(ToolClass::required_scope)
        .collect();
        assert_eq!(scopes.len(), 5);
    }
}
