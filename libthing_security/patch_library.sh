#!/bin/bash

# Script to patch libthing_security.so to use mock package signatures instead of Android ones
# This replaces JNI method signatures to point to our mock classes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
ORIGINAL_LIB="$LIB_DIR/libthing_security.so"
PATCHED_LIB="$LIB_DIR/libthing_security_patched.so"
BACKUP_LIB="$LIB_DIR/libthing_security_original.so"

echo "[+] Patching libthing_security.so for mock package signatures..."

# Check if original library exists
if [ ! -f "$ORIGINAL_LIB" ]; then
    echo "ERROR: $ORIGINAL_LIB not found!"
    exit 1
fi

# Create backup if it doesn't exist
if [ ! -f "$BACKUP_LIB" ]; then
    echo "[+] Creating backup of original library..."
    cp "$ORIGINAL_LIB" "$BACKUP_LIB"
fi

# Copy original to create patched version
cp "$ORIGINAL_LIB" "$PATCHED_LIB"

echo "[+] Applying patches to library signatures..."

# Define the signature replacements
# Note: We need to be careful about string lengths - they should match or we need to handle differently

declare -A REPLACEMENTS=(
    # Context class reference (same length)
    ["Landroid/content/Context;"]="Lmock/content/Context;    "
    
    # Method signatures for Context methods (shorter)
    ["android/content/Context"]="mock/content/Context"
    ["android/content/pm/PackageManager"]="mock/content/pm/PackageManager"
    ["android/content/res/AssetManager"]="mock/content/res/AssetManager"
    
    # PackageManager signature (keep same length by padding)
    ["()Landroid/content/pm/PackageManager;"]="()Lmock/content/pm/PackageManager;   "
    
    # AssetManager signature (keep same length by padding) 
    ["()Landroid/content/res/AssetManager;"]="()Lmock/content/res/AssetManager;    "
)

# Function to perform binary string replacement (preserves file size)
replace_in_binary() {
    local file="$1"
    local search="$2" 
    local replace="$3"
    
    # Use Python for size-preserving binary string replacement
    python3 -c "
import sys

def replace_binary_inplace(filename, old_str, new_str):
    try:
        with open(filename, 'rb') as f:
            data = bytearray(f.read())
        
        old_bytes = old_str.encode('utf-8')
        new_bytes = new_str.encode('utf-8')
        old_len = len(old_bytes)
        new_len = len(new_bytes)
        
        # Find the string in binary data
        pos = data.find(old_bytes)
        if pos != -1:
            if new_len <= old_len:
                # Overwrite in-place and pad with zeros
                data[pos:pos+new_len] = new_bytes
                # Fill remaining space with null bytes
                for i in range(pos+new_len, pos+old_len):
                    data[i] = 0
                
                with open(filename, 'wb') as f:
                    f.write(data)
                return True
            else:
                print(f'    ! ERROR: New string too long ({new_len} > {old_len})')
                return False
        return False
    except Exception as e:
        print(f'    ! ERROR: {e}')
        return False

old_str = '''$search'''
new_str = '''$replace'''

if replace_binary_inplace('$file', old_str, new_str):
    print('    ✓ Replacement applied (size preserved)')
else:
    print('    - String not found (may be expected)')
"
}

# Apply all replacements
for search in "${!REPLACEMENTS[@]}"; do
    replace="${REPLACEMENTS[$search]}"
    echo "  Replacing: '$search' -> '$replace'"
    
    replace_in_binary "$PATCHED_LIB" "$search" "$replace"
done

# Additional hexdump-based patching for binary signatures if needed
echo "[+] Checking for binary signature patterns..."

# Look for method signatures in hex format (null-terminated strings)
if command -v hexdump >/dev/null 2>&1; then
    echo "[+] Searching for Android package signatures in binary..."
    
    # Search for the specific patterns we're interested in
    if hexdump -C "$PATCHED_LIB" | grep -q "android/content"; then
        echo "  Found android/content references in binary"
    fi
    
    if hexdump -C "$PATCHED_LIB" | grep -q "Landroid/content"; then
        echo "  Found Landroid/content signatures in binary"
    fi
fi

# Verify the patched file
if [ -f "$PATCHED_LIB" ]; then
    echo "[+] Patched library created: $(basename "$PATCHED_LIB")"
    echo "[+] Original size: $(stat -c%s "$ORIGINAL_LIB") bytes"
    echo "[+] Patched size:  $(stat -c%s "$PATCHED_LIB") bytes"
    
    # Copy patched version over original for use
    cp "$PATCHED_LIB" "$ORIGINAL_LIB"
    echo "[+] Patched library activated"
    
    echo
    echo "To restore original library, run:"
    echo "  cp $BACKUP_LIB $ORIGINAL_LIB"
else
    echo "ERROR: Failed to create patched library"
    exit 1
fi

echo "[+] Library patching complete!"
