#!/bin/bash

# Build script to compile all Java mock classes into classes.dex
# This script should be run on a system with Android SDK/build tools

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build_java"
OUTPUT_DIR="$SCRIPT_DIR"

echo "[+] Building Java mock classes for fuzzing..."

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Find all Java files (including nested packages)
JAVA_FILES=(
    "$SCRIPT_DIR/com/thingclips/smart/security/jni/JNICLibrary.java"
    "$SCRIPT_DIR/mock/content/Context.java"
    "$SCRIPT_DIR/mock/content/pm/PackageManager.java"
    "$SCRIPT_DIR/mock/content/res/AssetManager.java"
    "$SCRIPT_DIR/mock/util/Log.java"
)

echo "[+] Found Java files:"
for file in "${JAVA_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "    - $(basename "$file")"
    else
        echo "    - $(basename "$file") [MISSING]"
        exit 1
    fi
done

# Check for required tools
if ! command -v javac >/dev/null 2>&1; then
    echo "ERROR: javac not found. Please install Java JDK."
    exit 1
fi

# Compile Java files to .class files
echo "[+] Compiling Java files to class files..."
javac -cp . -source 8 -target 8 -d "$BUILD_DIR" "${JAVA_FILES[@]}"

if [ $? -ne 0 ]; then
    echo "ERROR: Java compilation failed"
    exit 1
fi

echo "[+] Compilation successful. Generated .class files:"
find "$BUILD_DIR" -name "*.class" -exec basename {} \;

# Convert .class files to .dex
echo "[+] Converting .class files to classes.dex..."
cd "$BUILD_DIR"

# Use d8 (modern replacement for dx)
if command -v d8 >/dev/null 2>&1; then
    echo "[+] Using d8 to create dex file..."
    d8 --output "$OUTPUT_DIR/" $(find . -name "*.class")
else
    echo "ERROR: d8 tool not found. Please install Android SDK build-tools (d8 is the modern replacement for dx)"
    exit 1
fi

if [ $? -eq 0 ]; then
    echo "[+] Successfully created classes.dex"
    echo "[+] File size: $(du -h "$OUTPUT_DIR/classes.dex" | cut -f1)"
    
    # Verify the dex file
    if command -v dexdump >/dev/null 2>&1; then
        echo "[+] Verifying classes.dex content:"
        dexdump -f "$OUTPUT_DIR/classes.dex" | grep "Class descriptor" | head -10
    fi
else
    echo "ERROR: Failed to create classes.dex"
    exit 1
fi

# Cleanup
cd "$SCRIPT_DIR"
rm -rf "$BUILD_DIR"

echo "[+] Build complete! classes.dex is ready for fuzzing."
