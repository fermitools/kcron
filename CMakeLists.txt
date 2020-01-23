cmake_minimum_required (VERSION 3.11)

project(kcron)

set(VERSION "1.0")

set(LANGUAGES "C")

####
# CMake modules
include(FeatureSummary)
set_package_properties(kcron PROPERTIES
 URL "https://github.com/scientificlinux/kcron"
 DESCRIPTION "A utility for getting Kerberos credentials in scheduled jobs")

### Require out-of-source builds
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory and run cmake from there.")
endif()


###########
#add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

####
# My CMake files
include(doc/CMakeLists.txt)
include(src/C/CMakeLists.txt)
include(src/shell/CMakeLists.txt)

####
# Print out feature summary
feature_summary(WHAT ALL)
feature_summary(FILENAME ${CMAKE_CURRENT_BINARY_DIR}/features.log WHAT ALL)

