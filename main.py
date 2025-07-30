#!/usr/bin/env python3
"""
Password Generator & Manager
Main application entry point
"""

import sys
import os
from getpass import getpass
from password_manager import PasswordManager
from password_generator import PasswordGenerator
from utils import clear_screen, display_banner

def main_menu():
    """Display main menu options"""
    print("\n" + "="*50)
    print("PASSWORD GENERATOR & MANAGER")
    print("="*50)
    print("1. Generate Password")
    print("2. Generate Passphrase")
    print("3. Add Password Entry")
    print("4. View Password Entry")
    print("5. List All Entries")
    print("6. Update Password Entry")
    print("7. Delete Password Entry")
    print("8. Export Passwords")
    print("9. Import Passwords")
    print("10. Change Master Password")
    print("0. Exit")
    print("="*50)

def handle_password_generation(generator):
    """Handle password generation options"""
    while True:
        print("\nPassword Generation Options:")
        print("1. Standard Password")
        print("2. Custom Length Password")
        print("3. Password with Custom Character Set")
        print("4. Back to Main Menu")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            password = generator.generate_password()
            print(f"\nGenerated Password: {password}")
            
        elif choice == '2':
            try:
                length = int(input("Enter password length (8-128): "))
                password = generator.generate_password(length=length)
                print(f"\nGenerated Password: {password}")
            except ValueError:
                print("Invalid length. Please enter a number.")
                
        elif choice == '3':
            print("\nCharacter Set Options (y/n):")
            include_upper = input("Include uppercase letters? (y/n): ").lower() == 'y'
            include_lower = input("Include lowercase letters? (y/n): ").lower() == 'y'
            include_digits = input("Include digits? (y/n): ").lower() == 'y'
            include_symbols = input("Include symbols? (y/n): ").lower() == 'y'
            
            try:
                length = int(input("Enter password length: "))
                password = generator.generate_password(
                    length=length,
                    include_uppercase=include_upper,
                    include_lowercase=include_lower,
                    include_digits=include_digits,
                    include_symbols=include_symbols
                )
                print(f"\nGenerated Password: {password}")
            except ValueError:
                print("Invalid length. Please enter a number.")
                
        elif choice == '4':
            break
            
        else:
            print("Invalid option. Please try again.")

def handle_passphrase_generation(generator):
    """Handle passphrase generation"""
    while True:
        print("\nPassphrase Generation Options:")
        print("1. Standard Passphrase (4 words)")
        print("2. Custom Word Count")
        print("3. Custom Separator")
        print("4. Back to Main Menu")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            passphrase = generator.generate_passphrase()
            print(f"\nGenerated Passphrase: {passphrase}")
            
        elif choice == '2':
            try:
                word_count = int(input("Enter number of words (2-10): "))
                passphrase = generator.generate_passphrase(word_count=word_count)
                print(f"\nGenerated Passphrase: {passphrase}")
            except ValueError:
                print("Invalid word count. Please enter a number.")
                
        elif choice == '3':
            separator = input("Enter separator (default: -): ").strip() or '-'
            try:
                word_count = int(input("Enter number of words (default: 4): ") or "4")
                passphrase = generator.generate_passphrase(
                    word_count=word_count,
                    separator=separator
                )
                print(f"\nGenerated Passphrase: {passphrase}")
            except ValueError:
                print("Invalid word count. Please enter a number.")
                
        elif choice == '4':
            break
            
        else:
            print("Invalid option. Please try again.")

def main():
    """Main application loop"""
    try:
        # Initialize components
        manager = PasswordManager()
        generator = PasswordGenerator()
        
        # Display banner
        display_banner()
        
        # Get master password
        if manager.has_existing_vault():
            print("Existing vault found.")
            master_password = getpass("Enter master password: ")
            if not manager.authenticate(master_password):
                print("Invalid master password. Exiting.")
                return
        else:
            print("Creating new vault.")
            master_password = getpass("Create master password: ")
            confirm_password = getpass("Confirm master password: ")
            if master_password != confirm_password:
                print("Passwords don't match. Exiting.")
                return
            manager.initialize_vault(master_password)
            
        print("Authentication successful!")
        
        # Main application loop
        while True:
            main_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if choice == '1':
                handle_password_generation(generator)
                
            elif choice == '2':
                handle_passphrase_generation(generator)
                
            elif choice == '3':
                service = input("Enter service name: ").strip()
                username = input("Enter username: ").strip()
                password = getpass("Enter password (or press Enter to generate): ").strip()
                
                if not password:
                    password = generator.generate_password()
                    print(f"Generated password: {password}")
                
                url = input("Enter URL (optional): ").strip()
                notes = input("Enter notes (optional): ").strip()
                
                entry_id = manager.add_entry(service, username, password, url, notes)
                print(f"Entry added successfully with ID: {entry_id}")
                
            elif choice == '4':
                service = input("Enter service name to search: ").strip()
                entries = manager.search_entries(service)
                
                if entries:
                    for entry in entries:
                        print(f"\nID: {entry['id']}")
                        print(f"Service: {entry['service']}")
                        print(f"Username: {entry['username']}")
                        print(f"Password: {entry['password']}")
                        print(f"URL: {entry.get('url', 'N/A')}")
                        print(f"Notes: {entry.get('notes', 'N/A')}")
                        print(f"Created: {entry['created_at']}")
                        print(f"Updated: {entry['updated_at']}")
                else:
                    print("No entries found.")
                    
            elif choice == '5':
                entries = manager.list_all_entries()
                if entries:
                    print(f"\nFound {len(entries)} entries:")
                    for entry in entries:
                        print(f"ID: {entry['id']} | Service: {entry['service']} | Username: {entry['username']}")
                else:
                    print("No entries found.")
                    
            elif choice == '6':
                entry_id = input("Enter entry ID to update: ").strip()
                entry = manager.get_entry_by_id(entry_id)
                
                if entry:
                    print(f"Current entry: {entry['service']} - {entry['username']}")
                    
                    new_service = input(f"New service name ({entry['service']}): ").strip()
                    new_username = input(f"New username ({entry['username']}): ").strip()
                    new_password = getpass("New password (leave empty to keep current): ").strip()
                    new_url = input(f"New URL ({entry.get('url', '')}): ").strip()
                    new_notes = input(f"New notes ({entry.get('notes', '')}): ").strip()
                    
                    updates = {}
                    if new_service: updates['service'] = new_service
                    if new_username: updates['username'] = new_username
                    if new_password: updates['password'] = new_password
                    if new_url: updates['url'] = new_url
                    if new_notes: updates['notes'] = new_notes
                    
                    if updates:
                        manager.update_entry(entry_id, **updates)
                        print("Entry updated successfully.")
                    else:
                        print("No changes made.")
                else:
                    print("Entry not found.")
                    
            elif choice == '7':
                entry_id = input("Enter entry ID to delete: ").strip()
                entry = manager.get_entry_by_id(entry_id)
                
                if entry:
                    print(f"Entry: {entry['service']} - {entry['username']}")
                    confirm = input("Are you sure you want to delete this entry? (y/N): ").lower()
                    if confirm == 'y':
                        manager.delete_entry(entry_id)
                        print("Entry deleted successfully.")
                    else:
                        print("Deletion cancelled.")
                else:
                    print("Entry not found.")
                    
            elif choice == '8':
                filename = input("Enter export filename (default: passwords_export.json): ").strip()
                if not filename:
                    filename = "passwords_export.json"
                
                try:
                    manager.export_passwords(filename)
                    print(f"Passwords exported to {filename}")
                except Exception as e:
                    print(f"Export failed: {e}")
                    
            elif choice == '9':
                filename = input("Enter import filename: ").strip()
                if os.path.exists(filename):
                    try:
                        count = manager.import_passwords(filename)
                        print(f"Successfully imported {count} entries.")
                    except Exception as e:
                        print(f"Import failed: {e}")
                else:
                    print("File not found.")
                    
            elif choice == '10':
                current_password = getpass("Enter current master password: ")
                if manager.authenticate(current_password):
                    new_password = getpass("Enter new master password: ")
                    confirm_password = getpass("Confirm new master password: ")
                    
                    if new_password == confirm_password:
                        manager.change_master_password(new_password)
                        print("Master password changed successfully.")
                    else:
                        print("Passwords don't match.")
                else:
                    print("Invalid current password.")
                    
            elif choice == '0':
                print("Goodbye!")
                break
                
            else:
                print("Invalid option. Please try again.")
                
            input("\nPress Enter to continue...")
            clear_screen()
            
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()