project(SecLibFuzzer)
cmake_minimum_required(VERSION 3.8)

include_directories(AFTER ${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)


# Executables
# ===========

# Standalone fuzzer (without FUZZ_MODE) for testing with input files
add_executable(fuzz "fuzz.c")
target_compile_options(fuzz PRIVATE -g3 -O0 -ggdb)
set_property(TARGET fuzz APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-rpath=$ORIGIN -Wl,--export-dynamic")
target_link_libraries(fuzz log jenv thing_security_algorithm mbedtls mbedx509 mbedcrypto dl)

# AFL++ persistent fuzzer (with FUZZ_MODE) for stdin input
add_executable(fuzz_test "fuzz.c")
target_compile_definitions(fuzz_test PRIVATE FUZZ_MODE)
target_compile_options(fuzz_test PRIVATE -g3 -O0 -ggdb)
set_property(TARGET fuzz_test APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-rpath=$ORIGIN -Wl,--export-dynamic")
target_link_libraries(fuzz_test log jenv thing_security_algorithm mbedtls mbedx509 mbedcrypto dl)

# Custom target to push both binaries to Android device
add_custom_target(push
    COMMAND adb push ./fuzz /data/local/tmp/seclib/fuzz_crash_rep
    COMMAND adb push ./fuzz_test /data/local/tmp/seclib/
    COMMAND adb push ../lib/libthing_security.so /data/local/tmp/seclib/
    COMMAND adb push ../lib/libthing_security_algorithm.so /data/local/tmp/seclib/
    COMMAND adb push ../lib/libmbedtls.so /data/local/tmp/seclib/
    COMMAND adb push ../lib/libmbedx509.so /data/local/tmp/seclib/
    COMMAND adb push ../lib/libmbedcrypto.so /data/local/tmp/seclib/
    COMMAND adb push ../../jenv/build/libjenv.so /data/local/tmp/seclib/
    COMMAND adb push ../afl.js /data/local/tmp/seclib/
    COMMAND adb push ../mock/classes.dex /data/local/tmp/seclib/
    DEPENDS fuzz fuzz_test jni_dex
    COMMENT "Pushing fuzz binaries and target library to Android device"
)

# Custom target to build all Java classes (including mocks) and convert to classes.dex
add_custom_command(
    OUTPUT classes.dex
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/mock/build_classes.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS mock/com/thingclips/smart/security/jni/JNICLibrary.java 
            mock/mock/content/Context.java
            mock/mock/content/pm/PackageManager.java
            mock/mock/content/res/AssetManager.java
            mock/mock/util/Log.java
            mock/build_classes.sh
    COMMENT "Building all Java classes and mocks into classes.dex"
)

add_custom_target(jni_dex
    DEPENDS classes.dex
    COMMENT "Build Java classes and mock classes into dex file"
)

# Fallback target for systems without Android build tools (creates .class files only)
add_custom_target(java_only
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/mock/build_java_only.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS mock/com/thingclips/smart/security/jni/JNICLibrary.java 
            mock/mock/content/Context.java
            mock/mock/content/pm/PackageManager.java
            mock/mock/content/res/AssetManager.java
            mock/mock/util/Log.java
            mock/build_java_only.sh
    COMMENT "Build Java classes only (no dex conversion)"
)

# Ensure jni_dex is built with the default 'make' command
add_custom_target(all_build ALL
    DEPENDS fuzz fuzz_test jni_dex
    COMMENT "Build all C and Java targets"
)
