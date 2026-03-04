#!/usr/bin/env python3
"""
Apollo Identity Layer - Role Resolver
Implements Section 7.2 Role Hierarchy & Inheritance Resolution EXACTLY.

Authoritative implementation:
- Data-driven
- No hardcoded inheritance
- Neo4j traversal only
"""

import sys
import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Neo4j Aura Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+s://342034a8.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "342034a8")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "342034a8")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")


class IdentityRoleResolver:
    """
    Resolves effective roles using Neo4j INHERITS_FROM traversal.
    """

    def __init__(self, uri, username, password, database):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.database = database

    def close(self):
        if self.driver:
            self.driver.close()

    def verify_connection(self):
        try:
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False

    def resolve_roles(self, direct_roles: list[str]):
        """
        Implements Section 7.2 EXACTLY.

        1. Traverse INHERITS_FROM to root
        2. Deduplicate roles
        3. Compute max clearance (lowest level number)
        4. Aggregate domains
        """

        effective_roles = {}
        allowed_domains = set()

        with self.driver.session(database=self.database) as session:

            # -----------------------------------------------------------
            # Step 1-3: Resolve inheritance for each direct role
            # -----------------------------------------------------------
            for role_name in direct_roles:

                query = """
                MATCH (r:Role {name: $role_name, is_active: true})
                OPTIONAL MATCH (r)-[:INHERITS_FROM*0..]->(ancestor:Role)
                WHERE ancestor.is_active = true
                RETURN DISTINCT ancestor.name AS role,
                                ancestor.level AS level
                """

                result = session.run(query, role_name=role_name)

                for record in result:
                    role = record["role"]
                    level = record["level"]

                    if role not in effective_roles:
                        effective_roles[role] = level

            if not effective_roles:
                return {
                    "direct_roles": direct_roles,
                    "effective_roles": [],
                    "max_clearance_level": None,
                    "allowed_domains": []
                }

            # -----------------------------------------------------------
            # Step 5: Aggregate allowed domains
            # -----------------------------------------------------------
            domain_query = """
            MATCH (r:Role)
            WHERE r.name IN $roles
            MATCH (r)-[:ACCESSES_DOMAIN]->(d:Domain)
            RETURN DISTINCT d.name AS domain
            """

            domain_result = session.run(
                domain_query,
                roles=list(effective_roles.keys())
            )

            for record in domain_result:
                allowed_domains.add(record["domain"])

        # -----------------------------------------------------------
        # Step 4: Clearance calculation
        # Lower number = higher privilege
        # -----------------------------------------------------------
        max_clearance_level = min(effective_roles.values())

        return {
            "direct_roles": direct_roles,
            "effective_roles": sorted(effective_roles.keys()),
            "max_clearance_level": max_clearance_level,
            "allowed_domains": sorted(list(allowed_domains))
        }


def main():
    print("=" * 60)
    print("Apollo Identity Layer - Role Resolver")
    print("=" * 60)

    password = NEO4J_PASSWORD
    if not password:
        print("✗ Password not found in .env file (NEO4J_PASSWORD)")
        sys.exit(1)

    # Input direct roles
    direct_roles_input = input(
        "\nEnter direct roles (comma separated, use role NAME not role_id): "
    )

    direct_roles = [r.strip() for r in direct_roles_input.split(",") if r.strip()]

    if not direct_roles:
        print("✗ No roles provided")
        sys.exit(1)

    resolver = IdentityRoleResolver(
        NEO4J_URI,
        NEO4J_USERNAME,
        password,
        NEO4J_DATABASE
    )

    try:
        print("\n🔗 Connecting to Neo4j...")
        if not resolver.verify_connection():
            sys.exit(1)

        print("✓ Connected successfully")

        print("\n🔍 Resolving role hierarchy...\n")

        result = resolver.resolve_roles(direct_roles)

        if not result["effective_roles"]:
            print("⚠ No matching active roles found.")
            sys.exit(0)

        print("🧬 Effective Roles:")
        for r in result["effective_roles"]:
            print(f"  - {r}")

        print(f"\n🔐 Max Clearance Level: {result['max_clearance_level']}")

        print("\n📂 Allowed Domains:")
        for d in result["allowed_domains"]:
            print(f"  - {d}")

        print("\n✓ Resolution complete")

    except Exception as e:
        print(f"\n✗ Error resolving roles: {e}")
        sys.exit(1)

    finally:
        resolver.close()


if __name__ == "__main__":
    main()
