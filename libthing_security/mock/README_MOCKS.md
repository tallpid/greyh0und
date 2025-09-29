# Java Mock Classes for Android Fuzzing

## Overview

This directory contains Java mock classes designed to prevent crashes during fuzzing of the `libthing_security.so` native library. The main issue was that `doCommandNative` expects a valid Android Context object, but fuzzing was passing invalid object references.

## Files

### Mock Classes
- **`MockContext.java`** - Mock Android Context class with required methods:
  - `getPackageManager()` - Returns MockPackageManager
  - `getAssets()` - Returns MockAssetManager  
  - `getPackageName()`, `getString()`, etc.

- **`MockPackageManager.java`** - Mock PackageManager class:
  - `getNameForUid()`, `checkPermission()`, `hasSystemFeature()`

- **`MockAssetManager.java`** - Mock AssetManager class:
  - `open()`, `list()`, `close()`

- **`JNICLibrary.java`** - Updated with additional utility methods:
  - `checkStatus()` - Original method for native library
  - `createMockContext()` - Factory method to create mock context
  - Additional logging and utility methods

### Build Scripts
- **`build_classes.sh`** - Complete build script that creates `classes.dex`
- **`build_java_only.sh`** - Simple script that only compiles to `.class` files

## Usage

### Building classes.dex

1. **With Android SDK build tools:**
   ```bash
   ./build_classes.sh
   ```
   This creates `classes.dex` ready for use with the fuzzer.

2. **Without Android build tools (compile only):**
   ```bash
   ./build_java_only.sh
   ```
   This creates `.class` files in `java_classes/` directory.

### Integration with Fuzzer

The fuzzer (`fuzz.c`) should be updated to:

1. **Use MockContext instead of String objects:**
   ```c
   // Instead of creating a String object for jlong parameter:
   jclass mock_context_class = (*env)->FindClass(env, "MockContext");
   jobject mock_context = (*env)->NewObject(env, mock_context_class, constructor);
   jlong context_handle = (jlong)(uintptr_t)mock_context;
   ```

2. **Load the classes.dex with proper classpath:**
   ```c
   char* options[] = {
       "-Djava.class.path=/data/local/tmp/seclib/classes.dex"
   };
   ```

## Problem Solved

**Original Issue:**
```
Abort message: 'thread.cc:2097] Throwing new exception 'no non-static method "Ljava/lang/String;.getPackageManager()Landroid/content/pm/PackageManager;"'
```

**Root Cause:** The `doCommandNative` function was receiving a String object but trying to call Context methods on it.

**Solution:** Provide mock classes that implement the expected methods, preventing method resolution failures and allowing fuzzing to continue.

## Testing

After building and deploying:

1. Copy `classes.dex` to the device: `/data/local/tmp/seclib/`
2. Run the fuzzer with a crash file that previously triggered the Context method calls
3. Verify that mock methods are called instead of crashing:
   ```
   [Mock] getPackageManager() called
   [Mock] getAssets() called
   ```

## Notes

- These mock classes are designed for fuzzing only - they don't implement real Android functionality
- All methods return safe default values or log their calls
- The approach prevents crashes while allowing fuzzing to explore different code paths
- Mock methods can be extended as needed if additional Android API calls are discovered during fuzzing
