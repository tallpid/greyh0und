#!/bin/bash

# Simple build script using only javac (creates .class files)
# Use this if Android build tools are not available

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/java_classes"

echo "[+] Building Java mock classes (class files only)..."

# Clean and create build directory  
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Find all Java files
JAVA_FILES=(
    "$SCRIPT_DIR/mock/com/thingclips/smart/security/jni/JNICLibrary.java"
    "$SCRIPT_DIR/mock/mock/content/Context.java"
    "$SCRIPT_DIR/mock/mock/content/pm/PackageManager.java"
    "$SCRIPT_DIR/mock/mock/content/res/AssetManager.java"
    "$SCRIPT_DIR/mock/mock/util/Log.java"
)

echo "[+] Compiling Java files..."
javac -d "$BUILD_DIR" "${JAVA_FILES[@]}"

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[+] Generated .class files in: $BUILD_DIR"
    find "$BUILD_DIR" -name "*.class" -type f
    echo
    echo "NOTE: To create classes.dex, run the main build_classes.sh script"
    echo "      or manually use dx/d8 tools on the generated .class files"
else
    echo "ERROR: Compilation failed!"
    exit 1
fi
