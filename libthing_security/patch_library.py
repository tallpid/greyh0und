#!/usr/bin/env python3
"""
Binary library patcher for Android JNI fuzzing
Replaces Android package signatures with mock package signatures while preserving file size
"""

import os
import sys
import shutil
from pathlib import Path

class BinaryPatcher:
    def __init__(self, lib_path):
        self.lib_path = Path(lib_path)
        self.lib_dir = self.lib_path.parent
        self.backup_path = self.lib_dir / f"{self.lib_path.stem}_original{self.lib_path.suffix}"
        self.patched_path = self.lib_dir / f"{self.lib_path.stem}_patched{self.lib_path.suffix}"
        
        # Define signature replacements - new strings must be <= old string length
        self.replacements = {
            # Context class reference (25 -> 22 chars + 3 nulls = 25)
            b"Landroid/content/Context;": b"Lmock/content/Context;\x00\x00\x00",
            
            # PackageManager signature (37 -> 34 chars + 3 nulls = 37)  
            b"()Landroid/content/pm/PackageManager;": b"()Lmock/content/pm/PackageManager;\x00\x00\x00",
            
            # AssetManager signature (36 -> 33 chars + 3 nulls = 36)
            b"()Landroid/content/res/AssetManager;": b"()Lmock/content/res/AssetManager;\x00\x00\x00",
            
            # Method path signatures (shorter replacements with nulls)
            b"android/content/Context": b"mock/content/Context\x00\x00\x00",
            b"android/content/pm/PackageManager": b"mock/content/pm/PackageManager\x00\x00\x00",
            b"android/content/res/AssetManager": b"mock/content/res/AssetManager\x00\x00\x00",
            
            # Critical: Replace the getAssets method signature in the disassembly
            b"()Landroid/content/res/AssetManager;": b"()Lmock/content/res/AssetManager;\x00\x00\x00",
        }
    
    def create_backup(self):
        """Create backup of original library"""
        if not self.backup_path.exists():
            print(f"[+] Creating backup: {self.backup_path.name}")
            shutil.copy2(self.lib_path, self.backup_path)
        else:
            print(f"[+] Backup already exists: {self.backup_path.name}")
    
    def replace_binary_string(self, data, old_bytes, new_bytes):
        """Replace binary string while preserving file size"""
        old_len = len(old_bytes)
        new_len = len(new_bytes)
        
        if new_len > old_len:
            print(f"    ! ERROR: New string too long ({new_len} > {old_len})")
            return data, False
        
        # Find all occurrences
        pos = 0
        replacements_made = 0
        
        while True:
            pos = data.find(old_bytes, pos)
            if pos == -1:
                break
                
            # Replace in-place with null padding
            data[pos:pos + new_len] = new_bytes[:new_len]
            # Fill remaining space with null bytes if new string is shorter
            if new_len < old_len:
                data[pos + new_len:pos + old_len] = b'\x00' * (old_len - new_len)
            
            replacements_made += 1
            pos += old_len
        
        return data, replacements_made > 0
    
    def patch_library(self):
        """Apply all patches to the library"""
        print(f"[+] Patching {self.lib_path.name} for mock package signatures...")
        
        # Read original file
        try:
            with open(self.lib_path, 'rb') as f:
                data = bytearray(f.read())
        except IOError as e:
            print(f"ERROR: Cannot read {self.lib_path}: {e}")
            return False
        
        original_size = len(data)
        print(f"[+] Original size: {original_size} bytes")
        
        # Apply all replacements
        print("[+] Applying patches to library signatures...")
        total_replacements = 0
        
        for old_bytes, new_bytes in self.replacements.items():
            old_str = old_bytes.decode('utf-8', errors='replace').replace('\x00', '\\0')
            new_str = new_bytes.decode('utf-8', errors='replace').replace('\x00', '\\0')
            print(f"  Replacing: '{old_str}' -> '{new_str}'")
            
            data, replaced = self.replace_binary_string(data, old_bytes, new_bytes)
            if replaced:
                print(f"    ✓ Replacement applied (size preserved)")
                total_replacements += 1
            else:
                print(f"    - String not found (may be expected)")
        
        # Verify size preservation
        if len(data) != original_size:
            print(f"ERROR: File size changed! {original_size} -> {len(data)}")
            return False
        
        # Write patched file
        try:
            with open(self.patched_path, 'wb') as f:
                f.write(data)
        except IOError as e:
            print(f"ERROR: Cannot write {self.patched_path}: {e}")
            return False
        
        print(f"[+] Patched library created: {self.patched_path.name}")
        print(f"[+] Patched size: {len(data)} bytes (preserved)")
        print(f"[+] Total replacements: {total_replacements}")
        
        return True
    
    def activate_patch(self):
        """Replace original library with patched version"""
        if self.patched_path.exists():
            shutil.copy2(self.patched_path, self.lib_path)
            print(f"[+] Patched library activated")
            print(f"\nTo restore original library, run:")
            print(f"  cp {self.backup_path} {self.lib_path}")
            return True
        return False
    
    def verify_signatures(self):
        """Verify that Android signatures have been replaced"""
        try:
            with open(self.lib_path, 'rb') as f:
                content = f.read()
            
            android_refs = content.count(b'android/content')
            landroid_refs = content.count(b'Landroid/content')
            mock_refs = content.count(b'mock/content')
            lmock_refs = content.count(b'Lmock/content')
            
            print(f"[+] Signature verification:")
            print(f"  android/content references: {android_refs}")
            print(f"  Landroid/content references: {landroid_refs}")
            print(f"  mock/content references: {mock_refs}")
            print(f"  Lmock/content references: {lmock_refs}")
            
            if android_refs == 0 and landroid_refs == 0 and (mock_refs > 0 or lmock_refs > 0):
                print(f"  ✓ Android signatures successfully replaced with mock signatures")
                return True
            else:
                print(f"  ! Warning: Some Android signatures may remain")
                return False
                
        except IOError as e:
            print(f"ERROR: Cannot verify signatures: {e}")
            return False

def main():
    # Configuration
    lib_dir = Path(__file__).parent / "lib"
    lib_file = lib_dir / "libthing_security.so"
    
    if not lib_file.exists():
        print(f"ERROR: Library not found: {lib_file}")
        print(f"Expected location: {lib_file.absolute()}")
        sys.exit(1)
    
    # Create patcher instance
    patcher = BinaryPatcher(lib_file)
    
    # Create backup
    patcher.create_backup()
    
    # Apply patches
    if not patcher.patch_library():
        print("ERROR: Patching failed")
        sys.exit(1)
    
    # Activate patched library
    if not patcher.activate_patch():
        print("ERROR: Failed to activate patched library")
        sys.exit(1)
    
    # Verify results
    patcher.verify_signatures()
    
    print("[+] Library patching complete!")

if __name__ == "__main__":
    main()
