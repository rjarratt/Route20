list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/Route20")
cmake_minimum_required(VERSION 3.31 FATAL_ERROR)
project(Route20)
add_subdirectory(Route20)
target_sources(Route20
    PRIVATE
        CMakePresets.json
)
set_source_files_properties(CMakePresets.json PROPERTIES HEADER_FILE_ONLY ON)
