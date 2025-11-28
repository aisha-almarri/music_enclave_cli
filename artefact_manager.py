"""
Artefact management system implementing CRUD operations.
Follows Factory pattern for artefact creation from Unit 3 design.

This module implements the core business logic for artefact management
including all CRUD operations with proper security controls and audit logging.
The Factory pattern ensures consistent artefact creation while the
Repository pattern handles data persistence isolation.
"""
import os
import sqlite3
from database import Database
from models import Artefact, User
from security import SecurityManager

class ArtefactManager:
    """
    Implements Factory pattern for controlled artefact creation.
    Handles all CRUD operations for lyrics, scores, and recordings
    with proper security controls and integrity verification.
    
    Design Patterns Implemented:
    - Factory Pattern: Controlled artefact creation process
    - Repository Pattern: Data access abstraction
    - Strategy Pattern: Pluggable security mechanisms
    """

    def __init__(self, db: Database, security_manager: SecurityManager, user_manager):
        """
        Initialize artefact manager with required dependencies.
        
        Args:
            db: Database instance for data persistence
            security_manager: Security manager for encryption/decryption
            user_manager: User manager for authentication and authorization
        """
        self.db = db
        self.security = security_manager
        self.user_manager = user_manager
        self.supported_audio_formats = ['.mp3', '.wav', '.aac', '.flac', '.m4a']

    def _validate_file_type(self, file_path: str, artefact_type: str) -> bool:
        """
        Validate file type based on artefact type and file extension.
        
        Args:
            file_path: Path to the file to validate
            artefact_type: Type of artefact ('lyric', 'score', 'recording')
            
        Returns:
            bool: True if file type is valid, False otherwise
        """
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if artefact_type == 'recording':
            if file_ext not in self.supported_audio_formats:
                print(f"❌ Error: Recording files must be one of {', '.join(self.supported_audio_formats)}")
                print(f"   Received file: {file_path} (extension: {file_ext})")
                return False
        elif artefact_type == 'lyric':
            if file_ext not in ['.txt', '.doc', '.docx', '.pdf']:
                print(f"⚠️  Warning: Lyric files typically use .txt, .doc, .docx, or .pdf extensions")
                print(f"   Received file: {file_path} (extension: {file_ext})")
                # Don't fail, just warn for text files
        elif artefact_type == 'score':
            if file_ext not in ['.txt', '.pdf', '.musicxml', '.mxl']:
                print(f"⚠️  Warning: Score files typically use .txt, .pdf, .musicxml, or .mxl extensions")
                print(f"   Received file: {file_path} (extension: {file_ext})")
                # Don't fail, just warn for score files
        
        return True

    def _get_file_info(self, file_path: str) -> dict:
        """
        Get file information including size and type.
        
        Args:
            file_path: Path to the file
            
        Returns:
            dict: File information
        """
        try:
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            return {
                'size': file_size,
                'extension': file_ext,
                'size_mb': round(file_size / (1024 * 1024), 2) if file_size > 0 else 0
            }
        except Exception as e:
            print(f"❌ Error getting file info: {e}")
            return {'size': 0, 'extension': '', 'size_mb': 0}

    def _normalize_output_path(self, output_path: str) -> str:
        """
        Normalize and validate output path for downloads.
        Creates directories if needed and handles different path formats.
        
        Args:
            output_path: User-provided output path
            
        Returns:
            str: Normalized absolute path
        """
        # Handle relative paths (like "1.txt")
        if not os.path.isabs(output_path):
            # Make it relative to current working directory
            output_path = os.path.join(os.getcwd(), output_path)
        
        # Normalize path (handles mixed slashes, etc.)
        output_path = os.path.normpath(output_path)
        
        # Ensure directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                print(f"📁 Created directory: {output_dir}")
            except Exception as e:
                print(f"❌ Error creating directory {output_dir}: {e}")
                raise
        
        return output_path

    def _should_close_connection(self):
        """Check if connection should be closed based on database type."""
        return hasattr(self.db, 'db_path') and self.db.db_path != ":memory:"

    def create_artefact(self, file_path: str, title: str, description: str, 
                       artefact_type: str) -> bool:
        """
        Create a new artefact - implements CREATE from CRUD.
        """
        # Check user permissions - only creators and admins can upload
        if not self.user_manager.has_permission('creator'):
            print("❌ Insufficient permissions. Creator role required.")
            return False
        
        # Validate artefact type
        if artefact_type not in ['lyric', 'score', 'recording']:
            print("❌ Invalid artefact type. Must be 'lyric', 'score', or 'recording'")
            return False
        
        # Verify file exists
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return False
        
        # Validate file type based on artefact type
        if not self._validate_file_type(file_path, artefact_type):
            return False
        
        # Get file information
        file_info = self._get_file_info(file_path)
        print(f"📁 File: {os.path.basename(file_path)} ({file_info['size_mb']} MB, {file_info['extension']})")
        
        # Check file size limits (optional - for very large files)
        if file_info['size'] > 500 * 1024 * 1024:  # 500MB limit
            print("❌ Error: File size exceeds 500MB limit")
            return False
        
        conn = None
        try:
            print("🔄 Processing file...")
            print("  - Calculating checksum...")
            
            # Generate security components
            checksum = self.security.calculate_checksum(file_path)
            
            print("  - Generating encryption keys...")
            data_key = self.security.generate_data_key()
            encrypted_data_key = self.security.encrypt_data_key(data_key)
            timestamp = self.security.get_current_timestamp()
            
            print("  - Encrypting file content...")
            storage_path, checksum = self.security.encrypt_file(file_path, data_key)
            
            print("  - Storing metadata...")
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO artefacts 
                (owner_id, title, description, artefact_type, encrypted_file_path, 
                 checksum_sha256, encryption_key_encrypted, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (self.user_manager.current_user.id, title, description, artefact_type,
                  storage_path, checksum, encrypted_data_key, timestamp, timestamp))
            
            artefact_id = cursor.lastrowid
            conn.commit()
            
            # Log audit event
            self.db.log_audit_event(
                self.user_manager.current_user.id,
                f"ARTEFACT_CREATE:{artefact_type}:{title}",
                artefact_id
            )
            
            print(f"✅ Artefact '{title}' created successfully (ID: {artefact_id})")
            print(f"   - Type: {artefact_type}")
            print(f"   - File encrypted and stored at: {storage_path}")
            print(f"   - Checksum: {checksum[:16]}...")
            print(f"   - Timestamp: {timestamp}")
            print(f"   - File size: {file_info['size_mb']} MB")
            
            return True
            
        except Exception as e:
            print(f"❌ Error creating artefact: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if conn and self._should_close_connection():
                conn.close()

    def read_artefact(self, artefact_id: int, output_path: str) -> bool:
        """
        Read and decrypt an artefact - implements READ from CRUD.
        """
        current_user = self.user_manager.get_current_user()
        if not current_user:
            print("❌ Not authenticated")
            return False
        
        conn = None
        try:
            # Retrieve artefact metadata
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM artefacts WHERE id = ?', (artefact_id,))
            artefact_data = cursor.fetchone()
            
            if not artefact_data:
                print("❌ Artefact not found")
                return False
            
            # Create Artefact object
            artefact = Artefact(
                id=artefact_data['id'],
                owner_id=artefact_data['owner_id'],
                title=artefact_data['title'],
                description=artefact_data['description'],
                artefact_type=artefact_data['artefact_type'],
                encrypted_file_path=artefact_data['encrypted_file_path'],
                checksum_sha256=artefact_data['checksum_sha256'],
                encryption_key_encrypted=artefact_data['encryption_key_encrypted'],
                created_at=artefact_data['created_at'],
                updated_at=artefact_data['updated_at']
            )
            
            # Normalize output path
            try:
                output_path = self._normalize_output_path(output_path)
                print(f"📁 Output path: {output_path}")
            except Exception as e:
                print(f"❌ Invalid output path: {e}")
                return False
            
            print("🔓 Decrypting file...")
            # Decrypt data key and file content
            data_key = self.security.decrypt_data_key(artefact.encryption_key_encrypted)
            decrypted_data = self.security.decrypt_file(artefact.encrypted_file_path, data_key)
            
            # Verify integrity using decrypted content
            print("🔍 Verifying file integrity...")
            if not self.security.verify_decrypted_content(decrypted_data, artefact.checksum_sha256):
                print("❌ Artefact integrity check failed - checksum mismatch")
                print("   The file may have been tampered with or corrupted")
                self.db.log_audit_event(current_user.id, "INTEGRITY_CHECK_FAILED", artefact_id)
                return False
            print("✅ Integrity check passed - file is authentic")
            
            # Write decrypted file
            with open(output_path, 'wb') as output_file:
                output_file.write(decrypted_data)
            
            # Get output file info
            output_info = self._get_file_info(output_path)
            
            # Log successful retrieval
            self.db.log_audit_event(current_user.id, f"ARTEFACT_READ:{artefact_id}", artefact_id)
            
            print(f"✅ Artefact downloaded successfully!")
            print(f"   - Original title: {artefact.title}")
            print(f"   - Type: {artefact.artefact_type}")
            print(f"   - Saved to: {output_path}")
            print(f"   - File size: {output_info['size_mb']} MB")
            print(f"   - Created: {artefact.created_at}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error decrypting artefact: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if conn and self._should_close_connection():
                conn.close()

    def update_artefact(self, artefact_id: int, new_file_path: str = None, 
                       new_title: str = None, new_description: str = None) -> bool:
        """
        Update an artefact - implements UPDATE from CRUD.
        Handles both metadata updates and file replacements with proper security.
        
        When a file is updated, new security components are generated:
        - New encryption key
        - New checksum
        - Updated timestamp
        
        Args:
            artefact_id: ID of the artefact to update
            new_file_path: Optional new file to replace current one
            new_title: Optional new title
            new_description: Optional new description
            
        Returns:
            bool: True if update successful, False otherwise
        """
        current_user = self.user_manager.get_current_user()
        if not current_user:
            print("❌ Not authenticated")
            return False
        
        conn = None
        try:
            # Retrieve current artefact data
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM artefacts WHERE id = ?', (artefact_id,))
            artefact_data = cursor.fetchone()
            
            if not artefact_data:
                print("❌ Artefact not found")
                return False
            
            # Create Artefact object for permission checking
            artefact = Artefact(
                id=artefact_data['id'],
                owner_id=artefact_data['owner_id'],
                title=artefact_data['title'],
                description=artefact_data['description'],
                artefact_type=artefact_data['artefact_type'],
                encrypted_file_path=artefact_data['encrypted_file_path'],
                checksum_sha256=artefact_data['checksum_sha256'],
                encryption_key_encrypted=artefact_data['encryption_key_encrypted'],
                created_at=artefact_data['created_at'],
                updated_at=artefact_data['updated_at']
            )
            
            # Check permissions using RBAC - admin or owner can modify
            if not current_user.can_modify_artefact(artefact.owner_id):
                print("❌ Insufficient permissions to modify this artefact")
                return False
            
            # Validate new file if provided
            if new_file_path and not os.path.exists(new_file_path):
                print(f"❌ New file not found: {new_file_path}")
                return False
            
            if new_file_path:
                # Validate file type based on existing artefact type
                if not self._validate_file_type(new_file_path, artefact.artefact_type):
                    return False
            
            update_fields = []
            params = []
            
            # Handle title update
            if new_title:
                update_fields.append("title = ?")
                params.append(new_title)
                print(f"📝 Updating title to: {new_title}")
            
            # Handle description update
            if new_description:
                update_fields.append("description = ?")
                params.append(new_description)
                print(f"📝 Updating description to: {new_description}")
            
            # Handle file replacement
            if new_file_path and os.path.exists(new_file_path):
                print("🔄 Replacing file with new version...")
                
                # Get new file info
                new_file_info = self._get_file_info(new_file_path)
                print(f"   - New file: {os.path.basename(new_file_path)} ({new_file_info['size_mb']} MB)")
                
                # Generate new security components for updated file
                data_key = self.security.generate_data_key()
                encrypted_data_key = self.security.encrypt_data_key(data_key)
                
                # Encrypt new file
                storage_path, checksum = self.security.encrypt_file(new_file_path, data_key)
                
                update_fields.extend([
                    "checksum_sha256 = ?",
                    "encryption_key_encrypted = ?",
                    "encrypted_file_path = ?"
                ])
                params.extend([checksum, encrypted_data_key, storage_path])
                
                print(f"   - New checksum: {checksum[:16]}...")
                print(f"   - File re-encrypted and stored at: {storage_path}")
                
                # Remove old encrypted file
                if os.path.exists(artefact.encrypted_file_path):
                    try:
                        os.remove(artefact.encrypted_file_path)
                        print(f"   - Old encrypted file removed: {artefact.encrypted_file_path}")
                    except Exception as e:
                        print(f"⚠️  Warning: Could not remove old file: {e}")
            
            # Always update timestamp - individual timestamps as required
            update_fields.append("updated_at = ?")
            new_timestamp = self.security.get_current_timestamp()
            params.append(new_timestamp)
            
            params.append(artefact_id)
            
            # Perform database update if there are changes
            if update_fields:
                cursor.execute(f'''
                    UPDATE artefacts 
                    SET {', '.join(update_fields)}
                    WHERE id = ?
                ''', params)
                
                conn.commit()
                self.db.log_audit_event(current_user.id, f"ARTEFACT_UPDATE:{artefact_id}", artefact_id)
                print(f"✅ Artefact {artefact_id} updated successfully")
                print(f"   - Last modified: {new_timestamp}")
            else:
                print("ℹ️  No changes specified")
            
            return True
            
        except Exception as e:
            print(f"❌ Error updating artefact: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if conn and self._should_close_connection():
                conn.close()

    def delete_artefact(self, artefact_id: int) -> bool:
        """
        Delete an artefact - implements DELETE from CRUD.
        Removes both database record and encrypted file with proper cleanup.
        
        This operation requires proper permissions and performs:
        - RBAC permission verification
        - Secure file deletion
        - Database record removal
        - Comprehensive audit logging
        
        Args:
            artefact_id: ID of the artefact to delete
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        current_user = self.user_manager.get_current_user()
        if not current_user:
            print("❌ Not authenticated")
            return False
        
        conn = None
        try:
            # Retrieve artefact data for verification and cleanup
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM artefacts WHERE id = ?', (artefact_id,))
            artefact_data = cursor.fetchone()
            
            if not artefact_data:
                print("❌ Artefact not found")
                return False
            
            # Create Artefact object for permission checking
            artefact = Artefact(
                id=artefact_data['id'],
                owner_id=artefact_data['owner_id'],
                title=artefact_data['title'],
                description=artefact_data['description'],
                artefact_type=artefact_data['artefact_type'],
                encrypted_file_path=artefact_data['encrypted_file_path'],
                checksum_sha256=artefact_data['checksum_sha256'],
                encryption_key_encrypted=artefact_data['encryption_key_encrypted'],
                created_at=artefact_data['created_at'],
                updated_at=artefact_data['updated_at']
            )
            
            # Check permissions - only admin or owner can delete
            if not current_user.can_modify_artefact(artefact.owner_id):
                print("❌ Insufficient permissions to delete this artefact")
                return False
            
            # Delete encrypted file from storage
            if os.path.exists(artefact.encrypted_file_path):
                try:
                    os.remove(artefact.encrypted_file_path)
                    print(f"🗑️  Removed encrypted file: {artefact.encrypted_file_path}")
                except Exception as e:
                    print(f"⚠️  Warning: Could not remove encrypted file: {e}")
            
            # Delete database record
            cursor.execute('DELETE FROM artefacts WHERE id = ?', (artefact_id,))
            conn.commit()
            
            # Log the deletion event
            self.db.log_audit_event(current_user.id, f"ARTEFACT_DELETE:{artefact_id}", artefact_id)
            print(f"✅ Artefact {artefact_id} ('{artefact.title}') deleted successfully")
            
            return True
            
        except Exception as e:
            print(f"❌ Error deleting artefact: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if conn and self._should_close_connection():
                conn.close()

    def list_artefacts(self, user_only: bool = False) -> list:
        """
        List all artefacts or only current user's artefacts.
        Supports both user-specific and admin views.
        
        This method demonstrates the READ operation for multiple items
        and shows how RBAC affects data visibility.
        
        Args:
            user_only: If True, only show current user's artefacts
            
        Returns:
            list: List of artefact tuples (id, title, type, created_at, updated_at)
        """
        current_user = self.user_manager.get_current_user()
        if not current_user:
            print("❌ Not authenticated")
            return []
        
        conn = None
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Apply RBAC filtering - admins see all, others see only their own
            if user_only and current_user.role != 'admin':
                cursor.execute('''
                    SELECT id, title, artefact_type, created_at, updated_at 
                    FROM artefacts WHERE owner_id = ?
                    ORDER BY created_at DESC
                ''', (current_user.id,))
            else:
                cursor.execute('''
                    SELECT id, title, artefact_type, created_at, updated_at 
                    FROM artefacts 
                    ORDER BY created_at DESC
                ''')
            
            artefacts = cursor.fetchall()
            return artefacts
            
        except Exception as e:
            print(f"❌ Error listing artefacts: {e}")
            return []
        finally:
            if conn and self._should_close_connection():
                conn.close()

    def verify_artefact_integrity(self, artefact_id: int) -> bool:
        """
        Verify artefact integrity by recalculating checksum.
        Demonstrates the integrity verification capability required by assignment.
        
        This method recalculates the SHA-256 checksum of the stored encrypted file
        and compares it with the stored checksum to detect any tampering or corruption.
        
        Args:
            artefact_id: ID of the artefact to verify
            
        Returns:
            bool: True if integrity verified, False otherwise
        """
        current_user = self.user_manager.get_current_user()
        if not current_user:
            print("❌ Not authenticated")
            return False

        conn = None
        try:
            # Retrieve artefact information in a single connection
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Get both file path and encryption key in one query
            cursor.execute('''
                SELECT encrypted_file_path, checksum_sha256, encryption_key_encrypted 
                FROM artefacts WHERE id = ?
            ''', (artefact_id,))
            
            result = cursor.fetchone()
            if not result:
                print("❌ Artefact not found")
                return False

            file_path = result['encrypted_file_path']
            stored_checksum = result['checksum_sha256']
            encrypted_key = result['encryption_key_encrypted']

            print(f"🔍 Verifying integrity of artefact {artefact_id}...")
            print(f"   Stored checksum: {stored_checksum[:32]}...")

            # Decrypt the data key and file content
            data_key = self.security.decrypt_data_key(encrypted_key)
            decrypted_data = self.security.decrypt_file(file_path, data_key)

            # Verify using decrypted content
            if self.security.verify_decrypted_content(decrypted_data, stored_checksum):
                print("✅ Integrity check passed - checksums match")
                print("   The artefact has not been tampered with and is authentic")
                self.db.log_audit_event(current_user.id, f"INTEGRITY_VERIFY_PASS:{artefact_id}", artefact_id)
                return True
            else:
                print("❌ Integrity check failed - checksums do not match")
                print("   WARNING: The artefact may have been tampered with or corrupted")
                self.db.log_audit_event(current_user.id, f"INTEGRITY_VERIFY_FAIL:{artefact_id}", artefact_id)
                return False

        except Exception as e:
            print(f"❌ Error during integrity verification: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if conn and self._should_close_connection():
                conn.close()

    def get_artefact_info(self, artefact_id: int) -> dict:
        """
        Get detailed information about a specific artefact.
        Useful for displaying artefact metadata without downloading the file.
        
        Args:
            artefact_id: ID of the artefact to query
            
        Returns:
            dict: Artefact metadata or empty dict if not found
        """
        current_user = self.user_manager.get_current_user()
        if not current_user:
            return {}
        
        conn = None
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT a.*, u.username as owner_name 
                FROM artefacts a 
                JOIN users u ON a.owner_id = u.id 
                WHERE a.id = ?
            ''', (artefact_id,))
            
            result = cursor.fetchone()
            if result:
                # Get file size info for the encrypted file
                file_size = 0
                file_size_mb = 0
                if os.path.exists(result['encrypted_file_path']):
                    file_size = os.path.getsize(result['encrypted_file_path'])
                    file_size_mb = round(file_size / (1024 * 1024), 2)
                
                return {
                    'id': result['id'],
                    'title': result['title'],
                    'description': result['description'],
                    'type': result['artefact_type'],
                    'owner': result['owner_name'],
                    'created_at': result['created_at'],
                    'updated_at': result['updated_at'],
                    'checksum': result['checksum_sha256'][:32] + '...',
                    'file_size_mb': file_size_mb,
                    'file_size_bytes': file_size
                }
            return {}
            
        except Exception as e:
            print(f"❌ Error getting artefact info: {e}")
            return {}
        finally:
            if conn and self._should_close_connection():
                conn.close()