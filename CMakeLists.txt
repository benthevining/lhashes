cmake_minimum_required (VERSION 3.25 FATAL_ERROR)

project (
	lhashes
	VERSION 0.0.1
	LANGUAGES CXX C
	DESCRIPTION "C++ hashes library"
	HOMEPAGE_URL "https://github.com/benthevining/lhashes/")

set_property (DIRECTORY APPEND PROPERTY LABELS lhashes)

include (CMakeDependentOption)

cmake_dependent_option (LHASH_TESTS "Build the lhashes tests" "${lhashes_IS_TOP_LEVEL}" "NOT IOS"
						OFF)

cmake_dependent_option (LHASH_BENCH "Build the lhashes benchmarks" "${LHASH_TESTS}" "NOT IOS" OFF)

option (LHASH_DOCS "Build the lhashes docs" "${lhashes_IS_TOP_LEVEL}")

include (GNUInstallDirs)

set (LHASH_INSTALL_DEST "${CMAKE_INSTALL_LIBDIR}/cmake/lhashes"
	 CACHE STRING "Path where package files will be installed, relative to the install prefix")

mark_as_advanced (LHASH_INSTALL_DEST LHASH_TESTS LHASH_BENCH LHASH_DOCS)

set_property (DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_LIST_DIR}/logs"
										"${CMAKE_CURRENT_LIST_DIR}/deploy")

# use the directory-scoped commands so that Catch2 gets these flags too
if (EMSCRIPTEN)
	add_compile_options (-sNO_DISABLE_EXCEPTION_CATCHING -fexceptions)
	add_link_options (-fexceptions)
endif ()

set (CMAKE_CXX_VISIBILITY_PRESET hidden)
set (CMAKE_VISIBILITY_INLINES_HIDDEN ON)

add_library (lhashes)
add_library (limes::lhashes ALIAS lhashes)

target_compile_features (lhashes PUBLIC cxx_std_20)

set_target_properties (lhashes PROPERTIES DEBUG_POSTFIX -d VERSION "${lhashes_VERSION}"
										  SOVERSION "${lhashes_VERSION_MAJOR}")

set (public_header include/lhashes/lhashes.h)

set (
	private_headers
	include/lhashes/lhashes_common.h
	include/lhashes/lhashes_hash.h
	include/lhashes/lhashes_md5.h
	include/lhashes/lhashes_sha1.h
	include/lhashes/lhashes_sha224.h
	include/lhashes/lhashes_sha256.h
	include/lhashes/lhashes_sha384.h
	include/lhashes/lhashes_sha512.h)

set (export_header "${CMAKE_CURRENT_BINARY_DIR}/generated/lhashes/lhashes_Export.h")

include (GenerateExportHeader)

# cmake-format: off
generate_export_header (
	lhashes
	EXPORT_MACRO_NAME LHASH_EXPORT
	NO_EXPORT_MACRO_NAME LHASH_NO_EXPORT
	EXPORT_FILE_NAME "${export_header}")
# cmake-format: on

target_sources (lhashes # PUBLIC "${public_header}"
				PRIVATE ${private_headers} "${export_header}")

target_include_directories (
	lhashes
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
		   $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
		   $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

install (FILES "${public_header}" "${export_header}" ${private_headers}
		 DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/lhashes" COMPONENT lhashes_dev)

if (WIN32)
	target_compile_definitions (lhashes PRIVATE NOMINMAX)
endif ()

add_subdirectory (src)

install (
	TARGETS lhashes
	EXPORT lhashes
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lhashes NAMELINK_COMPONENT lhashes_dev
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lhashes_dev
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT lhashes
	INCLUDES
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install (
	EXPORT lhashes
	NAMESPACE limes::
	FILE Targets.cmake
	DESTINATION "${LHASH_INSTALL_DEST}"
	COMPONENT lhashes_dev)

include (CMakePackageConfigHelpers)

write_basic_package_version_file (lhashes-config-version.cmake VERSION "${lhashes_VERSION}"
								  COMPATIBILITY SameMajorVersion)

configure_package_config_file (cmake/lhashes-config.in lhashes-config.cmake
							   INSTALL_DESTINATION "${LHASH_INSTALL_DEST}" NO_SET_AND_CHECK_MACRO)

install (FILES "${CMAKE_CURRENT_BINARY_DIR}/lhashes-config-version.cmake"
			   "${CMAKE_CURRENT_BINARY_DIR}/lhashes-config.cmake"
		 DESTINATION "${LHASH_INSTALL_DEST}" COMPONENT lhashes_dev)

include (CPackComponent)

cpack_add_component (
	lhashes DISPLAY_NAME "Limes hashes library"
	DESCRIPTION "The Limes C++ hashing library. This is the runtime component needed by end users."
	GROUP limes_hashes)

cpack_add_component (
	lhashes_dev
	DISPLAY_NAME "Limes hashes library headers"
	DESCRIPTION
		"Development package for the Limes C++ hashing library. This component includes the library's header files and CMake package files."
	GROUP limes_hashes
	DEPENDS lhashes)

cpack_add_component_group (limes_hashes DISPLAY_NAME "Limes hashes"
						   DESCRIPTION "Limes hashes library" PARENT_GROUP limes)

if (LHASH_TESTS)
	enable_testing ()

	add_subdirectory (tests)

	include (CTest)
endif ()

if (LHASH_BENCH)
	enable_testing ()

	add_subdirectory (bench)

	if (NOT LHASH_TESTS)
		include (CTest)
	endif ()
endif ()

if (LHASH_DOCS)
	add_subdirectory (docs)
endif ()

if (lhashes_IS_TOP_LEVEL)
	include (CPack)
endif ()
