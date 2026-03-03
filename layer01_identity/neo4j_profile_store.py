import logging
from typing import Optional

from neo4j import GraphDatabase

from .context_builder import BaseUserProfileStore
from .models import ClearanceLevel, UserProfile

logger = logging.getLogger(__name__)

class Neo4jUserProfileStore(BaseUserProfileStore):
    """
    Fetches the internal user profile data from Neo4j (staff/doctors).
    Used to build the full SecurityContext on login.
    """

    def __init__(self, uri, username, password, database="neo4j"):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.database = database

    def close(self):
        if self.driver:
            self.driver.close()

    async def get(self, user_id: str) -> Optional[UserProfile]:
        """
        Fetches the user from the staff/doctors graph.
        Returns a populated UserProfile or None.
        """
        query = """
        MATCH (u)
        WHERE (u:Staff OR u:Doctor) AND u.user_id = $uid
        RETURN u.user_id AS user_id,
               u.department AS department,
               u.facility_id AS facility,
               u.clearance_level AS clearance_level,
               u.is_active AS is_active
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, uid=user_id)
                record = result.single()
                
                if record:
                    return UserProfile(
                        user_id=record["user_id"],
                        department=record["department"],
                        facility=record["facility"],
                        clearance_level=ClearanceLevel(record["clearance_level"]) if record["clearance_level"] else ClearanceLevel.PUBLIC,
                        is_active=record["is_active"] if record["is_active"] is not None else True,
                    )
                else:
                    logger.warning("User '%s' not found in Neo4j", user_id)
                    return None
                    
        except Exception as e:
            logger.error("Failed to fetch UserProfile from Neo4j: %s", e)
            return None

    async def is_active(self, user_id: str) -> bool:
        """Returns False if the account is suspended or deprovisioned."""
        profile = await self.get(user_id)
        if profile:
            return profile.is_active
        # Default True so login can proceed as basic public if not found
        return True
