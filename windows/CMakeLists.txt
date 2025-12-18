# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.14)

# Project-level configuration.
set(PROJECT_NAME "biometric_signature")
project(${PROJECT_NAME} LANGUAGES CXX)

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent
# versions of CMake.
cmake_policy(VERSION 3.14...3.25)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "biometric_signature_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "biometric_signature_plugin.cpp"
  "biometric_signature_plugin.h"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  "include/biometric_signature/biometric_signature_plugin_c_api.h"
  "include/biometric_signature/biometric_signature_plugin.h"
  "biometric_signature_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)

# Don't use apply_standard_settings because it disables exceptions which WinRT requires.
# Instead, apply settings manually with exceptions enabled.
target_compile_features(${PLUGIN_NAME} PUBLIC cxx_std_17)
target_compile_options(${PLUGIN_NAME} PRIVATE /W4 /WX /wd"4100")
target_compile_options(${PLUGIN_NAME} PRIVATE /EHsc)
target_compile_options(${PLUGIN_NAME} PRIVATE /await)
target_compile_definitions(${PLUGIN_NAME} PRIVATE "$<$<CONFIG:Debug>:_DEBUG>")

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(${PLUGIN_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}")

# Link against Flutter and Windows libraries
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin)
target_link_libraries(${PLUGIN_NAME} PRIVATE windowsapp)

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(biometric_signature_bundled_libraries
  ""
  PARENT_SCOPE
)

