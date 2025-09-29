project(NativeFuzzme)
cmake_minimum_required(VERSION 3.8)

include_directories(AFTER ${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)

# Executables
# ===========

# Standalone fuzzer (without FUZZ_MODE) for testing with input files
add_executable(fuzz "fuzz.c")
target_compile_options(fuzz PRIVATE -g3 -O0 -ggdb)
set_property(TARGET fuzz APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-rpath=$ORIGIN -Wl,--export-dynamic")
target_link_libraries(fuzz log jenv BleLib dl)

# AFL++ persistent fuzzer (with FUZZ_MODE) for stdin input
add_executable(fuzz_test "fuzz.c")
target_compile_definitions(fuzz_test PRIVATE FUZZ_MODE)
target_compile_options(fuzz_test PRIVATE -g3 -O0 -ggdb)
set_property(TARGET fuzz_test APPEND_STRING PROPERTY LINK_FLAGS " -Wl,-rpath=$ORIGIN -Wl,--export-dynamic")
target_link_libraries(fuzz_test log jenv BleLib dl)

# Custom target to push both binaries to Android device
add_custom_target(push
    COMMAND adb push fuzz /data/local/tmp/
    COMMAND adb push fuzz_test /data/local/tmp/
    DEPENDS fuzz fuzz_test
    COMMENT "Pushing both fuzz binaries to Android device"
)

