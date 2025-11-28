"""
Data models representing the Object Model from Unit 3 Class Diagram.
Implements encapsulation, abstraction, inheritance, and polymorphism principles.

These models provide the logical structure for the Secure Music Copyright Enclave
system as defined in the original UML Class Diagram.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class User:
    """
    User model representing different roles in the system.
    Implements RBAC from the Use Case Diagram with three distinct roles.
    """
    id: int
    username: str
    password_hash: str
    role: str  # 'admin', 'creator', 'viewer'
    created_at: datetime
    
    def can_modify_artefact(self, artefact_owner_id: int) -> bool:
        """
        Implement RBAC permissions from Use Case Diagram.
        - Admin: can modify any artefact
        - Creator: can only modify own artefacts  
        - Viewer: cannot modify any artefacts
        """
        if self.role == 'admin':
            return True
        elif self.role == 'creator' and self.id == artefact_owner_id:
            return True
        return False
    
    def can_view_artefact(self) -> bool:
        """All roles can view artefacts, but with different access levels."""
        return True

@dataclass
class Artefact:
    """
    Abstract Artefact class implementation from Unit 3 Class Diagram.
    Encapsulates metadata, encryption keys, checksum and timestamp.
    
    This serves as the base class for all artefact types (lyric, score, recording)
    following the inheritance hierarchy from the original design.
    """
    id: int
    owner_id: int
    title: str
    description: str
    artefact_type: str  # 'lyric', 'score', 'recording'
    encrypted_file_path: str
    checksum_sha256: str
    encryption_key_encrypted: bytes
    created_at: datetime
    updated_at: datetime
    
    def get_metadata(self) -> dict:
        """Abstract common metadata access for all artefact types."""
        return {
            'id': self.id,
            'title': self.title,
            'type': self.artefact_type,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

@dataclass
class AuditEntry:
    """
    AuditEntry class for tracking system activities.
    Supports security monitoring and compliance requirements from NIST CSF.
    """
    id: int
    user_id: int
    artefact_id: Optional[int]
    action: str
    timestamp: datetime