cmake_minimum_required(VERSION 3.20)
project(tenrec_fixtures LANGUAGES C)

# Test fixtures need stable, debuggable binaries — not optimized output. We want
# IDA to see meaningful function/variable names, predictable call patterns, and
# string literals laid out as the source describes them.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# Collect every fixture binary in one place so the build orchestrator doesn't
# have to walk per-target subdirectories.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/binaries")

# Cross-compiler flags applied to every fixture target.
function(tenrec_apply_fixture_flags target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /Od /Zi)
    else()
        target_compile_options(${target} PRIVATE -O0 -g -fno-omit-frame-pointer)
        # Disable PIE so addresses inside the binary are more predictable for
        # tooling — IDA still handles PIE fine, this is just a niceness.
        if(NOT APPLE)
            target_link_options(${target} PRIVATE -no-pie)
            set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE OFF)
        endif()
    endif()
endfunction()

# Add new fixture targets here.
add_subdirectory(sources/basic)
add_subdirectory(sources/types_zoo)
add_subdirectory(sources/data_layout)
