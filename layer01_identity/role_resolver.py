"""
SentinelSQL — Layer 01: Identity & Context Layer
role_resolver.py — Role hierarchy traversal and effective-role computation.

The resolver flattens a role graph into a complete list of effective permissions.
Downstream layers (Policy Resolution, Retrieval) only need to check effective_roles[].

Two backends are provided:
  - DictRoleResolver   → in-memory dict (use now, for development / testing)
  - Neo4jRoleResolver  → graph traversal via Cypher (plug in when Layer 02 is ready)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections import deque

logger = logging.getLogger(__name__)


# ─── ROLE HIERARCHY (Dict backend) ────────────────────────────────────────────
#
# Key   = a role name
# Value = list of roles it directly INHERITS (i.e. also grants)
#
# Example: SENIOR_ANALYST inherits DATA_ANALYST, which inherits VIEWER.
#          So a SENIOR_ANALYST has effective roles:
#          [SENIOR_ANALYST, DATA_ANALYST, REPORT_VIEWER, VIEWER, BASE_USER]
#
DEFAULT_ROLE_HIERARCHY: dict[str, list[str]] = {
    # ── Admin tier ─────────────────────────────────────────────────────────
    "ADMIN":              ["DATA_ANALYST", "REPORT_VIEWER", "AUDITOR"],
    "SUPER_ADMIN":        ["ADMIN"],

    # ── Analyst tier ───────────────────────────────────────────────────────
    "SENIOR_ANALYST":     ["DATA_ANALYST"],
    "DATA_ANALYST":       ["REPORT_VIEWER", "VIEWER"],

    # ── Healthcare-specific roles ──────────────────────────────────────────
    "ATTENDING_PHYSICIAN":["TREATING_PROVIDER", "CLINICAL_VIEWER"],
    "TREATING_PROVIDER":  ["CLINICAL_VIEWER"],
    "CLINICAL_VIEWER":    ["VIEWER"],
    "NURSE":              ["CLINICAL_VIEWER"],
    "PHARMACIST":         ["CLINICAL_VIEWER"],

    # ── Compliance / audit ────────────────────────────────────────────────
    "AUDITOR":            ["REPORT_VIEWER"],
    "COMPLIANCE_OFFICER": ["AUDITOR", "REPORT_VIEWER"],

    # ── Base roles (no inheritance) ────────────────────────────────────────
    "REPORT_VIEWER":      ["BASE_USER"],
    "VIEWER":             ["BASE_USER"],
    "BASE_USER":          [],
}


# ─── ABSTRACT BASE ────────────────────────────────────────────────────────────

class BaseRoleResolver(ABC):
    @abstractmethod
    def resolve(self, raw_roles: list[str]) -> list[str]:
        """
        Given a list of raw roles from the IdP, return the complete
        flattened list of effective roles (including all inherited roles).
        Duplicates are removed; order is deterministic.
        """
        ...


# ─── DICT BACKEND (use during development) ────────────────────────────────────

class DictRoleResolver(BaseRoleResolver):
    """
    BFS traversal over an in-memory dict hierarchy.
    O(n) where n = total reachable roles from the starting set.
    """

    def __init__(self, hierarchy: dict[str, list[str]] | None = None):
        self.hierarchy = hierarchy or DEFAULT_ROLE_HIERARCHY

    def resolve(self, raw_roles: list[str]) -> list[str]:
        if not raw_roles:
            logger.warning("resolve() called with empty raw_roles — returning BASE_USER only")
            return ["BASE_USER"]

        effective: set[str] = set()
        queue: deque[str] = deque(raw_roles)

        while queue:
            role = queue.popleft()
            if role in effective:
                continue

            if role not in self.hierarchy:
                logger.warning("Unknown role encountered: '%s' — treating as leaf (no inheritance)", role)

            effective.add(role)
            for inherited in self.hierarchy.get(role, []):
                if inherited not in effective:
                    queue.append(inherited)

        result = sorted(effective)  # deterministic ordering
        logger.debug("Resolved %s → %s", raw_roles, result)
        return result

    def add_role(self, role: str, inherits: list[str]) -> None:
        """Dynamically extend the hierarchy at runtime (e.g. from DB config)."""
        self.hierarchy[role] = inherits

    def get_all_roles(self) -> list[str]:
        return sorted(self.hierarchy.keys())


# ─── NEO4J BACKEND (swap in when Layer 02 / Knowledge Graph is ready) ─────────

class Neo4jRoleResolver(BaseRoleResolver):
    """
    Traverses the INHERITS_FROM relationships in Neo4j.

    Cypher query used:
        MATCH (r:Role {name: $role})-[:INHERITS_FROM*0..]->(inherited:Role)
        RETURN DISTINCT inherited.name AS role_name

    Usage:
        resolver = Neo4jRoleResolver(driver=neo4j_driver)
        effective = resolver.resolve(["SENIOR_ANALYST"])
    """

    def __init__(self, driver):
        self._driver = driver

    def resolve(self, raw_roles: list[str]) -> list[str]:
        effective: set[str] = set()

        with self._driver.session() as session:
            for role in raw_roles:
                result = session.run(
                    """
                    MATCH (r:Role {name: $role})-[:INHERITS_FROM*0..]->(inherited:Role)
                    RETURN DISTINCT inherited.name AS role_name
                    """,
                    role=role,
                )
                for record in result:
                    effective.add(record["role_name"])

        return sorted(effective)


# ─── FACTORY ──────────────────────────────────────────────────────────────────

def get_role_resolver(backend: str = "dict", **kwargs) -> BaseRoleResolver:
    """
    Factory function — switch between backends via config.

    Args:
        backend: "dict" (default) or "neo4j"
        **kwargs: passed to the chosen resolver constructor

    Example:
        resolver = get_role_resolver("dict")
        resolver = get_role_resolver("neo4j", driver=neo4j_driver)
    """
    if backend == "dict":
        return DictRoleResolver(hierarchy=kwargs.get("hierarchy"))
    elif backend == "neo4j":
        if "driver" not in kwargs:
            raise ValueError("Neo4jRoleResolver requires a 'driver' kwarg")
        return Neo4jRoleResolver(driver=kwargs["driver"])
    else:
        raise ValueError(f"Unknown role resolver backend: '{backend}'")
