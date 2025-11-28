#!/usr/bin/env python3
"""
Secure Music Copyright Enclave - CLI Application
Main entry point implementing the command-line interface.

This application implements the Secure Music Copyright Enclave system
designed in Unit 3, providing secure storage and management of digital
music artefacts with enterprise-grade security features.

Design Patterns Implemented:
- Repository Pattern: Data access isolation in database operations
- Strategy Pattern: Pluggable cryptographic providers in security operations  
- Factory Pattern: Controlled artefact creation in artefact management

Security Standards Compliance:
- ISO/IEC 27000:2018 - Information security management
- NIST Cybersecurity Framework v1.1 - Security controls
- OWASP Secure Coding Practices - Password and encryption standards
"""

import os
import sys
import getpass
from database import Database
from user_manager import UserManager
from artefact_manager import ArtefactManager
from security import SecurityManager

class MusicEnclaveCLI:
    """
    Main CLI application class.
    Implements the command-line interface for the Secure Music Copyright Enclave.
    
    This class provides a secure, user-friendly interface for managing
    digital music artefacts with comprehensive security controls and
    role-based access control as specified in the Unit 3 design.
    """
    
    def __init__(self):
        """
        Initialize the application with secure master key setup.
        Implements secure startup following defense-in-depth principles.
        """
        self.db = Database()
        # Secure master key setup - no hardcoded passwords
        self.setup_master_key()
        self.user_manager = UserManager(self.db)
        self.artefact_manager = ArtefactManager(self.db, self.security_manager, self.user_manager)
    
    def setup_master_key(self):
        """
        Securely setup master encryption key.
        Implements secure key management strategy from Unit 3 design.
        
        The master key is used to wrap individual file encryption keys,
        following the key lifecycle management specified in Appendix 1.
        """
        print("\n" + "="*60)
        print("    SECURE MASTER KEY SETUP")
        print("="*60)
        print("This key encrypts all file encryption keys in the system.")
        print("It provides the foundation for all cryptographic operations.")
        print("")
        print("🔐 SECURITY NOTES:")
        print("- Keep this password secure and memorable")
        print("- It cannot be recovered if lost")
        print("- All encrypted files become inaccessible without it")
        print("- Use a strong password with mixed characters")
        print("="*60)
        
        while True:
            try:
                master_password = getpass.getpass("\nEnter master encryption password: ")
                
                if not master_password:
                    print("❌ Error: Master password cannot be empty!")
                    continue
                
                if len(master_password) < 8:
                    print("❌ Error: Password must be at least 8 characters long!")
                    continue
                    
                confirm_password = getpass.getpass("Confirm master encryption password: ")
                
                if master_password == confirm_password:
                    self.security_manager = SecurityManager(master_password)
                    print("✅ Master key configured successfully!")
                    print("🔒 Cryptographic system initialized and ready")
                    break
                else:
                    print("❌ Error: Passwords do not match! Please try again.")
            except KeyboardInterrupt:
                print("\n\n⚠️  Setup cancelled by user. Application exiting...")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error setting up master key: {e}")
                print("Please check your system configuration and try again.")
                sys.exit(1)
    
    def display_menu(self):
        """
        Display appropriate menu based on authentication and role.
        Implements dynamic menu system that adapts to user permissions.
        """
        print("\n" + "="*60)
        print("    SECURE MUSIC COPYRIGHT ENCLAVE")
        print("="*60)
        
        current_user = self.user_manager.get_current_user()
        
        if not current_user:
            # Not authenticated - public menu
            print("1. Login to existing account")
            print("2. Register new account")
            print("3. System Information")
            print("4. Exit Application")
            print("\n💡 First-time users should register an admin account.")
            print("   Roles: admin (full access), creator (upload), viewer (read-only)")
        else:
            # Authenticated - show role-based menu
            print(f"👤 Welcome, {current_user.username} ({current_user.role})")
            print("\n--- ARTEFACT MANAGEMENT ---")
            print("1.  List My Artefacts")
            print("2.  Upload New Artefact (Creator/Admin)")
            print("3.  Download Artefact")
            print("4.  Update Artefact (Owner/Admin)")
            print("5.  Delete Artefact (Owner/Admin)")
            print("6.  Verify Artefact Integrity")
            print("7.  View Artefact Details")
            
            if current_user.role == 'admin':
                print("\n--- ADMINISTRATION ---")
                print("8.  List All System Users")
                print("9.  List All System Artefacts")
                print("10. System Statistics & Reports")
            
            print("\n--- ACCOUNT & SYSTEM ---")
            print("0.  Logout")
            print("00. Exit Application")
        
        print("="*60)
    
    def handle_upload_artefact(self):
        """
        Handle artefact upload process.
        Implements CREATE operation from CRUD functionality.
        
        This method follows the Factory Pattern for consistent artefact
        creation and automatically applies all security controls:
        - AES-256 encryption
        - SHA-256 checksum calculation
        - Individual timestamping
        - Audit logging
        """
        print("\n" + "="*50)
        print("    UPLOAD NEW ARTEFACT")
        print("="*50)
        
        # Input validation with comprehensive error handling
        file_path = input("Enter file path: ").strip()
        if not file_path:
            print("❌ Error: File path cannot be empty!")
            return
        
        if not os.path.exists(file_path):
            print(f"❌ Error: File not found at '{file_path}'")
            print("💡 Please check the path and try again.")
            return
        
        # Display file information for confirmation
        try:
            file_size = os.path.getsize(file_path)
            print(f"📁 File found: {os.path.basename(file_path)} ({file_size} bytes)")
        except Exception as e:
            print(f"❌ Error accessing file: {e}")
            return
        
        title = input("Enter title: ").strip()
        if not title:
            print("❌ Error: Title cannot be empty!")
            return
            
        description = input("Enter description: ").strip()
        if not description:
            description = "No description provided"
        
        print("\n📝 Artefact types:")
        print("   - lyric: Song lyrics, poetry, text content")
        print("   - score: Music scores, sheet music, notation")
        print("   - recording: Audio files, music recordings")
        
        artefact_type = input("Enter artefact type: ").strip().lower()
        
        if artefact_type not in ['lyric', 'score', 'recording']:
            print("❌ Error: Invalid artefact type. Must be 'lyric', 'score', or 'recording'")
            return
        
        # Confirm upload details
        print(f"\n📋 UPLOAD SUMMARY:")
        print(f"   Title: {title}")
        print(f"   Type: {artefact_type}")
        print(f"   File: {file_path}")
        print(f"   Description: {description}")
        
        confirm = input("\nProceed with upload? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Upload cancelled.")
            return
        
        # Attempt artefact creation with progress feedback
        print(f"\n🔄 Uploading '{title}'...")
        print("   - Calculating file checksum...")
        print("   - Generating encryption keys...")
        print("   - Encrypting file content...")
        
        if self.artefact_manager.create_artefact(file_path, title, description, artefact_type):
            print(f"✅ Upload successful!")
            print("🔒 File has been encrypted and stored securely")
            print("📊 Checksum verified for integrity protection")
        else:
            print("❌ Upload failed. Please check permissions and try again.")
    
    def handle_download_artefact(self):
        """
        Handle artefact download process.
        Implements READ operation from CRUD functionality.
        
        Includes comprehensive security checks:
        - User authentication verification
        - Artefact existence check
        - Integrity verification via checksum
        - Secure decryption process
        - Audit logging
        """
        print("\n" + "="*50)
        print("    DOWNLOAD ARTEFACT")
        print("="*50)
        
        artefact_id = input("Enter artefact ID: ").strip()
        if not artefact_id:
            print("❌ Error: Artefact ID cannot be empty!")
            return
        
        try:
            artefact_id = int(artefact_id)
            if artefact_id <= 0:
                print("❌ Error: Artefact ID must be positive!")
                return
        except ValueError:
            print("❌ Error: Invalid artefact ID. Must be a number!")
            return
        
        output_path = input("Enter output file path: ").strip()
        if not output_path:
            print("❌ Error: Output path cannot be empty!")
            return
        
        # Check if output directory exists and create if necessary
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                print(f"📁 Created output directory: {output_dir}")
            except Exception as e:
                print(f"❌ Error creating output directory: {e}")
                return
        
        print(f"\n🔍 Retrieving artefact {artefact_id}...")
        print("   - Verifying permissions...")
        print("   - Checking file integrity...")
        print("   - Decrypting content...")
        
        if self.artefact_manager.read_artefact(artefact_id, output_path):
            print(f"✅ Download successful!")
            
            # Show download verification
            try:
                file_size = os.path.getsize(output_path)
                print(f"📁 File saved: {output_path} ({file_size} bytes)")
            except:
                print(f"📁 File saved: {output_path}")
        else:
            print("❌ Download failed. Artefact may not exist or you lack permissions.")
    
    def handle_list_artefacts(self, admin_view=False):
        """
        List artefacts with optional admin view.
        Demonstrates READ operation and RBAC permissions.
        
        Args:
            admin_view: If True, shows all system artefacts (admin only)
        """
        artefacts = self.artefact_manager.list_artefacts(user_only=not admin_view)
        
        if not artefacts:
            print("No artefacts found in the system.")
            return
        
        view_type = "ALL SYSTEM ARTEFACTS" if admin_view else "MY ARTEFACTS"
        print(f"\n📋 {view_type}")
        print("="*80)
        print(f"{'ID':<4} {'Type':<8} {'Title':<25} {'Created':<19} {'Updated':<19}")
        print("-" * 80)
        
        for artefact in artefacts:
            artefact_id, title, artefact_type, created, updated = artefact
            # Truncate long titles for better display
            display_title = title[:22] + "..." if len(title) > 25 else title.ljust(25)
            created_display = created[:16] if created else "Unknown"
            updated_display = updated[:16] if updated else "Unknown"
            
            print(f"{artefact_id:<4} {artefact_type:<8} {display_title:<25} {created_display:<19} {updated_display:<19}")
        
        print(f"\nTotal: {len(artefacts)} artefact(s)")
    
    def handle_view_artefact_details(self):
        """
        Display detailed information about a specific artefact.
        Shows metadata without downloading the actual file content.
        """
        print("\n" + "="*50)
        print("    ARTEFACT DETAILS")
        print("="*50)
        
        artefact_id = input("Enter artefact ID: ").strip()
        if not artefact_id:
            print("❌ Error: Artefact ID cannot be empty!")
            return
        
        try:
            artefact_id = int(artefact_id)
            if artefact_id <= 0:
                print("❌ Error: Artefact ID must be positive!")
                return
        except ValueError:
            print("❌ Error: Invalid artefact ID. Must be a number!")
            return
        
        # Get detailed artefact information
        artefact_info = self.artefact_manager.get_artefact_info(artefact_id)
        
        if not artefact_info:
            print("❌ Artefact not found or access denied.")
            return
        
        print(f"\n📄 ARTEFACT DETAILS (ID: {artefact_info['id']})")
        print("="*40)
        print(f"Title:       {artefact_info['title']}")
        print(f"Type:        {artefact_info['type']}")
        print(f"Owner:       {artefact_info['owner']}")
        print(f"Created:     {artefact_info['created_at']}")
        print(f"Last Updated: {artefact_info['updated_at']}")
        print(f"File Size:   {artefact_info.get('file_size_mb', 'Unknown')} MB")
        print(f"Checksum:    {artefact_info.get('checksum', 'Unknown')}")
        print(f"Status:      Available for download")
        print("\n💡 Use option 6 to verify file integrity")
        print("💡 Use option 3 to download this artefact")
    
    def handle_system_statistics(self):
        """
        Display system statistics and reports (admin only).
        Provides overview of system usage and security status.
        """
        if not self.user_manager.has_permission('admin'):
            print("❌ Error: Administrator privileges required!")
            return
            
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Get user statistics
        cursor.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
        role_stats = cursor.fetchall()
        
        # Get artefact statistics
        cursor.execute("SELECT artefact_type, COUNT(*) as count FROM artefacts GROUP BY artefact_type")
        artefact_stats = cursor.fetchall()
        
        # Get total audit entries
        cursor.execute("SELECT COUNT(*) as count FROM audit_log")
        audit_count = cursor.fetchone()['count']
        
        # Get recent activity
        cursor.execute("""
            SELECT action, timestamp 
            FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT 5
        """)
        recent_activity = cursor.fetchall()
        
        conn.close()
        
        print("\n" + "="*50)
        print("    SYSTEM STATISTICS & REPORTS")
        print("="*50)
        
        print("\n👥 USER STATISTICS:")
        total_users = sum(stat['count'] for stat in role_stats)
        print(f"   Total Users: {total_users}")
        for stat in role_stats:
            print(f"   - {stat['role'].capitalize()}s: {stat['count']}")
            
        print("\n📁 ARTEFACT STATISTICS:")
        total_artefacts = sum(stat['count'] for stat in artefact_stats)
        print(f"   Total Artefacts: {total_artefacts}")
        for stat in artefact_stats:
            print(f"   - {stat['artefact_type'].capitalize()}s: {stat['count']}")
            
        print(f"\n📊 SECURITY METRICS:")
        print(f"   Audit Log Entries: {audit_count}")
        
        storage_files = os.listdir("storage") if os.path.exists("storage") else []
        print(f"   Encrypted Files: {len(storage_files)}")
        
        print(f"\n⏰ RECENT ACTIVITY (Last 5 events):")
        for activity in recent_activity:
            action = activity['action'][:30] + "..." if len(activity['action']) > 30 else activity['action']
            timestamp = activity['timestamp'][:16] if activity['timestamp'] else "Unknown"
            print(f"   - {timestamp}: {action}")
    
    def handle_system_information(self):
        """
        Display system information and security features.
        Available to all users including unauthenticated ones.
        """
        print("\n" + "="*50)
        print("    SYSTEM INFORMATION")
        print("="*50)
        
        print("\n🎵 SECURE MUSIC COPYRIGHT ENCLAVE")
        print("   Version: 1.0")
        print("   Developed as per Unit 3 Design Specification")
        
        print("\n🔒 SECURITY FEATURES:")
        print("   - AES-256 File Encryption")
        print("   - SHA-256 Integrity Checksums") 
        print("   - Role-Based Access Control (RBAC)")
        print("   - Comprehensive Audit Logging")
        print("   - Secure Password Hashing (bcrypt)")
        print("   - Individual File Timestamping")
        
        print("\n📁 SUPPORTED ARTEFACT TYPES:")
        print("   - Lyrics: Text files, song lyrics, poetry")
        print("   - Scores: Music notation, sheet music")
        print("   - Recordings: MP3, WAV, AAC, FLAC audio files")
        
        print("\n👥 USER ROLES:")
        print("   - Admin: Full system access and management")
        print("   - Creator: Upload and manage own artefacts") 
        print("   - Viewer: Read-only access to artefacts")
        
        # Show basic system stats (without sensitive info)
        if os.path.exists("music_enclave.db"):
            db_size = os.path.getsize("music_enclave.db")
            print(f"\n📊 SYSTEM STATUS:")
            print(f"   Database: {db_size} bytes")
            
            if os.path.exists("storage"):
                storage_files = len(os.listdir("storage"))
                print(f"   Encrypted Files: {storage_files}")
        
        print("\n💡 Get started by registering an account and uploading your first artefact!")
    
    def run(self):
        """
        Main application loop with enhanced error handling.
        Implements the primary user interaction flow with comprehensive
        security and error management.
        """
        print("\n🚀 Initializing Secure Music Copyright Enclave...")
        print("📍 System based on Unit 3 design with ISO/IEC 27000 and NIST CSF compliance")
        print("🔐 All files are encrypted with AES-256 and integrity-protected with SHA-256")
        
        while True:
            try:
                self.display_menu()
                choice = input("\nEnter your choice: ").strip()
                
                current_user = self.user_manager.get_current_user()
                
                if not current_user:
                    # Not authenticated menu
                    if choice == '1':
                        self.handle_login()
                    elif choice == '2':
                        self.handle_register()
                    elif choice == '3':
                        self.handle_system_information()
                    elif choice == '4':
                        print("\nThank you for using Secure Music Copyright Enclave. Goodbye! 👋")
                        break
                    else:
                        print("❌ Invalid choice. Please select 1, 2, 3, or 4.")
                
                else:
                    # Authenticated menu
                    if choice == '1':
                        self.handle_list_artefacts()
                    elif choice == '2':
                        self.handle_upload_artefact()
                    elif choice == '3':
                        self.handle_download_artefact()
                    elif choice == '4':
                        self.handle_update_artefact()
                    elif choice == '5':
                        self.handle_delete_artefact()
                    elif choice == '6':
                        self.handle_verify_integrity()
                    elif choice == '7':
                        self.handle_view_artefact_details()
                    elif choice == '8' and current_user.role == 'admin':
                        self.handle_list_users()
                    elif choice == '9' and current_user.role == 'admin':
                        self.handle_list_artefacts(admin_view=True)
                    elif choice == '10' and current_user.role == 'admin':
                        self.handle_system_statistics()
                    elif choice == '0':
                        self.user_manager.logout()
                        print("✅ Logged out successfully.")
                    elif choice == '00':
                        print("\nThank you for using Secure Music Copyright Enclave. Goodbye! 👋")
                        break
                    else:
                        print("❌ Invalid choice or insufficient permissions.")
                        
            except KeyboardInterrupt:
                print("\n\n⚠️  Operation cancelled by user.")
            except Exception as e:
                print(f"\n💥 Unexpected error: {e}")
                print("Please try again or contact system administrator if the problem persists.")
    
    def handle_login(self):
        """Handle user login with secure password input."""
        print("\n" + "="*50)
        print("    USER LOGIN")
        print("="*50)
        
        username = input("Username: ").strip()
        if not username:
            print("❌ Error: Username cannot be empty!")
            return
            
        password = getpass.getpass("Password: ")
        if not password:
            print("❌ Error: Password cannot be empty!")
            return
        
        print("\n🔐 Authenticating...")
        self.user_manager.login(username, password)
    
    def handle_register(self):
        """Handle user registration with comprehensive input validation."""
        print("\n" + "="*50)
        print("    USER REGISTRATION")
        print("="*50)
        
        username = input("Username: ").strip()
        if not username:
            print("❌ Error: Username cannot be empty!")
            return
        if len(username) < 3:
            print("❌ Error: Username must be at least 3 characters!")
            return
            
        password = getpass.getpass("Password: ")
        if not password:
            print("❌ Error: Password cannot be empty!")
            return
        if len(password) < 6:
            print("❌ Error: Password must be at least 6 characters!")
            return
        
        print("\n👥 Available roles:")
        print("   - viewer: Read-only access to artefacts")
        print("   - creator: Upload and manage own artefacts") 
        print("   - admin: Full system access and management")
        
        role = input("Role (default: viewer): ").strip().lower()
        if not role:
            role = 'viewer'
        
        if role not in ['viewer', 'creator', 'admin']:
            print("❌ Error: Invalid role. Must be 'viewer', 'creator', or 'admin'")
            return
        
        print(f"\n📋 REGISTRATION SUMMARY:")
        print(f"   Username: {username}")
        print(f"   Role: {role}")
        print(f"   Password: {'*' * len(password)}")
        
        confirm = input("\nCreate this account? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Registration cancelled.")
            return
        
        if self.user_manager.register_user(username, password, role):
            print(f"✅ Registration successful! You can now login as {role}.")
        else:
            print("❌ Registration failed. Username may already exist.")
    
    def handle_update_artefact(self):
        """
        Handle artefact update process.
        Implements UPDATE operation from CRUD functionality.
        """
        print("\n" + "="*50)
        print("    UPDATE ARTEFACT")
        print("="*50)
        
        artefact_id = input("Enter artefact ID to update: ").strip()
        if not artefact_id:
            print("❌ Error: Artefact ID cannot be empty!")
            return
        
        try:
            artefact_id = int(artefact_id)
            if artefact_id <= 0:
                print("❌ Error: Artefact ID must be positive!")
                return
        except ValueError:
            print("❌ Error: Invalid artefact ID. Must be a number!")
            return
        
        print("\n📝 Leave fields blank to keep current values:")
        
        new_title = input("New title: ").strip()
        new_description = input("New description: ").strip()
        new_file_path = input("New file path: ").strip()
        
        # Validate new file path if provided
        if new_file_path and not os.path.exists(new_file_path):
            print(f"❌ Error: New file not found at '{new_file_path}'")
            return
        
        # Convert empty strings to None
        new_title = new_title if new_title else None
        new_description = new_description if new_description else None
        new_file_path = new_file_path if new_file_path else None
        
        # Check if any changes are being made
        if not any([new_title, new_description, new_file_path]):
            print("❌ No changes specified. Update cancelled.")
            return
        
        print(f"\n🔄 Updating artefact {artefact_id}...")
        if self.artefact_manager.update_artefact(artefact_id, new_file_path, new_title, new_description):
            print("✅ Update successful! Timestamp and checksum updated.")
        else:
            print("❌ Update failed. You may not have permission or artefact doesn't exist.")
    
    def handle_delete_artefact(self):
        """
        Handle artefact deletion process.
        Implements DELETE operation from CRUD functionality.
        """
        print("\n" + "="*50)
        print("    DELETE ARTEFACT")
        print("="*50)
        
        artefact_id = input("Enter artefact ID to delete: ").strip()
        if not artefact_id:
            print("❌ Error: Artefact ID cannot be empty!")
            return
        
        try:
            artefact_id = int(artefact_id)
            if artefact_id <= 0:
                print("❌ Error: Artefact ID must be positive!")
                return
        except ValueError:
            print("❌ Error: Invalid artefact ID. Must be a number!")
            return
        
        # Safety confirmation - require explicit confirmation
        print(f"\n⚠️  WARNING: This action cannot be undone!")
        print(f"   Artefact {artefact_id} will be permanently deleted.")
        print(f"   Both database record and encrypted file will be removed.")
        
        confirm = input(f"Type 'DELETE' to confirm deletion: ").strip()
        
        if confirm == 'DELETE':
            print(f"\n🗑️  Deleting artefact {artefact_id}...")
            if self.artefact_manager.delete_artefact(artefact_id):
                print("✅ Deletion successful! Artefact and encrypted file removed.")
            else:
                print("❌ Deletion failed. You may not have permission or artefact doesn't exist.")
        else:
            print("❌ Deletion cancelled. Type 'DELETE' exactly to confirm deletion.")
    
    def handle_verify_integrity(self):
        """Handle artefact integrity verification with checksum validation."""
        print("\n" + "="*50)
        print("    VERIFY ARTEFACT INTEGRITY")
        print("="*50)
        
        # Show available artefacts first
        artefacts = self.artefact_manager.list_artefacts(user_only=True)
        if not artefacts:
            print("❌ No artefacts found. Please upload an artefact first.")
            return
        
        print("📋 Your available artefacts:")
        for artefact in artefacts[:5]:  # Show first 5
            artefact_id, title, artefact_type, created, updated = artefact
            print(f"   ID: {artefact_id} - {title} ({artefact_type})")
        
        if len(artefacts) > 5:
            print(f"   ... and {len(artefacts) - 5} more artefacts")
        
        artefact_id = input("\nEnter artefact ID to verify: ").strip()
        if not artefact_id:
            print("❌ Error: Artefact ID cannot be empty!")
            return
        
        try:
            artefact_id = int(artefact_id)
            if artefact_id <= 0:
                print("❌ Error: Artefact ID must be positive!")
                return
            
            # Verify artefact exists
            artefact_exists = any(art[0] == artefact_id for art in artefacts)
            if not artefact_exists:
                print(f"❌ Error: Artefact ID {artefact_id} not found in your artefacts!")
                return
                
        except ValueError:
            print("❌ Error: Invalid artefact ID. Must be a number!")
            return
        
        print(f"\n🔍 Verifying integrity of artefact {artefact_id}...")
        self.artefact_manager.verify_artefact_integrity(artefact_id)
    
    def handle_list_users(self):
        """Handle user listing with formatted output (admin only)."""
        users = self.user_manager.list_users()
        
        if not users:
            print("No users found in system.")
            return
        
        print("\n" + "="*50)
        print("    SYSTEM USERS")
        print("="*50)
        print(f"{'ID':<4} {'Username':<15} {'Role':<10} {'Created':<19}")
        print("-" * 55)
        
        for user in users:
            user_id, username, role, created = user
            created_display = created[:16] if created else "Unknown"
            print(f"{user_id:<4} {username:<15} {role:<10} {created_display:<19}")
        
        print(f"\nTotal: {len(users)} user(s)")


def main():
    """
    Application entry point with comprehensive error handling.
    Implements secure startup and graceful shutdown procedures.
    """
    try:
        print("🚀 Starting Secure Music Copyright Enclave...")
        print("🔒 Enterprise-grade security system initializing...")
        
        app = MusicEnclaveCLI()
        app.run()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Application interrupted by user. Shutting down securely...")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Critical application error: {e}")
        print("Please check your system configuration and try again.")
        print("If the problem persists, contact system administrator.")
        sys.exit(1)


if __name__ == "__main__":
    """
    Secure Music Copyright Enclave - Main Entry Point
    
    This application provides a secure platform for managing digital music
    artefacts with comprehensive security controls as designed in Unit 3.
    
    Security Implementation:
    - All files encrypted with AES-256 before storage
    - SHA-256 checksums for integrity verification
    - Role-Based Access Control (RBAC) with three distinct roles
    - Comprehensive audit logging of all operations
    - Secure password hashing using bcrypt
    - Individual timestamps for creation and modification
    
    Design Patterns:
    - Repository Pattern: Data access isolation
    - Strategy Pattern: Pluggable cryptographic providers  
    - Factory Pattern: Controlled artefact creation
    """
    main()