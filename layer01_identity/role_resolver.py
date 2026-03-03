from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Dict

class BaseRoleResolver(ABC):
    """Abstract base class for role resolution."""
    
    @abstractmethod
    def resolve(self, direct_roles: List[str]) -> List[str]:
        """Resolves direct roles to a complete list of effective roles (including inherited)."""
        pass

    @abstractmethod
    def get_role_metadata(self, roles: List[str]) -> Dict:
        """Returns metadata like allowed_domains and max_clearance_level based on roles."""
        pass

class DictRoleResolver(BaseRoleResolver):
    """A simple dictionary-based role resolver for testing and fallback."""
    
    def __init__(self, hierarchy: Dict[str, List[str]] = None):
        self.hierarchy = hierarchy or {}
        
    def resolve(self, direct_roles: List[str]) -> List[str]:
        """Resolves direct roles to a flat list of effective roles recursively."""
        effective_roles = set()
        
        def _traverse(role: str):
            if role in effective_roles:
                return
            effective_roles.add(role)
            for parent in self.hierarchy.get(role, []):
                _traverse(parent)
                
        for r in direct_roles:
            _traverse(r)
            
        return sorted(list(effective_roles))

    def get_all_roles(self) -> List[str]:
        """Returns all known roles in the hierarchy."""
        roles = set(self.hierarchy.keys())
        for parents in self.hierarchy.values():
            roles.update(parents)
        return list(roles)

    def get_role_metadata(self, roles: List[str]) -> Dict:
        return {"allowed_domains": [], "max_clearance_level": None}
