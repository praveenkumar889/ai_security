import logging
from typing import List, Dict

from neo4j import GraphDatabase

from .role_resolver import BaseRoleResolver

logger = logging.getLogger(__name__)

class Neo4jRoleResolver(BaseRoleResolver):
    """
    Resolves effective roles using Neo4j INHERITS_FROM traversal.
    Queries the Knowledge Graph to resolve raw IdP roles into effective roles.
    """

    def __init__(self, uri, username, password, database="neo4j", enable_caching=True):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.database = database
        self.enable_caching = enable_caching
        self._cache = {}

    def close(self):
        if self.driver:
            self.driver.close()

    def get_all_roles(self):
        """Returns all role names currently active in the neo4j database."""
        query = "MATCH (r:Role) WHERE r.is_active = true RETURN r.name as name"
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query)
                return [record["name"] for record in result]
        except Exception as e:
            logger.error("Failed to retrieve roles from Neo4j: %s", e)
            return []

    def resolve(self, direct_roles: List[str]) -> List[str]:
        """
        Traverses the role hierarchy graph starting from the user's direct roles
        following the -[:INHERITS_FROM*0..]-> paths to find all effective roles.
        """
        if not direct_roles:
            return []

        # Simple caching
        cache_key = tuple(sorted(direct_roles))
        if self.enable_caching and cache_key in self._cache:
            return self._cache[cache_key]

        effective_roles = set()
        
        try:
            with self.driver.session(database=self.database) as session:
                for role_name in direct_roles:
                    query = """
                    MATCH (r:Role {name: $role_name, is_active: true})
                    OPTIONAL MATCH (r)-[:INHERITS_FROM*0..]->(ancestor:Role)
                    WHERE ancestor.is_active = true
                    RETURN DISTINCT ancestor.name AS role
                    """
                    result = session.run(query, role_name=role_name)
                    
                    found = False
                    for record in result:
                        if record["role"]:
                            effective_roles.add(record["role"])
                            found = True
                    
                    # If not found in graph, at least include the direct role
                    # to fulfill basic access.
                    if not found:
                        effective_roles.add(role_name)

        except Exception as e:
            logger.error(f"Neo4j traversal failed: {e}")
            # Fallback: grant direct roles only on failure
            effective_roles.update(direct_roles)

        resolved_list = sorted(list(effective_roles))
        
        if self.enable_caching:
            self._cache[cache_key] = resolved_list

        return resolved_list

    def get_role_metadata(self, roles: List[str]) -> Dict:
        """Computes max clearance level and allowed domains from roles."""
        if not roles:
            return {"allowed_domains": [], "max_clearance_level": None}

        allowed_domains = set()
        max_clearance = None

        query = """
        MATCH (r:Role)
        WHERE r.name IN $roles
        OPTIONAL MATCH (r)-[:ACCESSES_DOMAIN]->(d:Domain)
        RETURN r.level AS level, collect(d.name) AS domains
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, roles=roles)
                levels = []
                for record in result:
                    if record["level"] is not None:
                        levels.append(record["level"])
                    
                    for domain in record["domains"]:
                        if domain:
                            allowed_domains.add(domain)
                
                if levels:
                    max_clearance = min(levels)

        except Exception as e:
            logger.error("Failed to fetch role metadata: %s", e)

        return {
            "allowed_domains": sorted(list(allowed_domains)),
            "max_clearance_level": max_clearance
        }
