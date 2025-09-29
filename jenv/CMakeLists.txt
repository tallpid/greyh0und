project(JavaEnvironmentInit)
cmake_minimum_required(VERSION 3.8)

include_directories(AFTER ${CMAKE_SOURCE_DIR}/include)
find_library(log-lib log REQUIRED)
find_library(nativehelper-lib nativehelper REQUIRED)

# Native Library
# ==============

add_library(jenv SHARED "jenv.c")

# Link required libraries for Android JNI
target_link_libraries(jenv 
    ${log-lib} 
    ${nativehelper-lib}
    dl
)

# Export dynamic symbols to resolve libsigchain issues
set_target_properties(jenv PROPERTIES
    LINK_FLAGS "-Wl,--export-dynamic"
)
