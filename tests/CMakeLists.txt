# ======================================================================================
#  __    ____  __  __  ____  ___
# (  )  (_  _)(  \/  )( ___)/ __)
#  )(__  _)(_  )    (  )__) \__ \
# (____)(____)(_/\/\_)(____)(___/
#
#  This file is part of the Limes open source library and is licensed under the terms of the GNU Public License.
#
#  Commercial licenses are available; contact the maintainers at ben.the.vining@gmail.com to inquire for details.
#
# ======================================================================================

function (lhash_copy_dlls target)
	if (WIN32)
		add_custom_command (
			TARGET "${target}" POST_BUILD
			COMMAND "${CMAKE_COMMAND}" -E copy -t $<TARGET_FILE_DIR:${target}>
					$<TARGET_RUNTIME_DLLS:${target}> USES_TERMINAL COMMAND_EXPAND_LISTS)
	endif ()
endfunction ()

#

include (FetchContent)

FetchContent_Declare (
	Catch2
	GIT_REPOSITORY https://github.com/catchorg/Catch2.git
	GIT_TAG origin/devel
	GIT_SHALLOW ON
	FIND_PACKAGE_ARGS 3 GLOBAL)

FetchContent_MakeAvailable (Catch2)

if (catch2_SOURCE_DIR)
	list (APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
endif ()

include (Catch)

add_executable (lhashes_tests)

set_target_properties (lhashes_tests PROPERTIES MACOSX_BUNDLE OFF)

target_sources (lhashes_tests PRIVATE md5.cpp sha1.cpp sha224.cpp sha256.cpp sha384.cpp sha512.cpp)

target_link_libraries (lhashes_tests PRIVATE Catch2::Catch2WithMain limes::lhashes)

lhash_copy_dlls (lhashes_tests)

# cmake-format: off
catch_discover_tests (
	lhashes_tests
	EXTRA_ARGS
		--warn NoAssertions
		--order rand
		--verbosity high
	TEST_PREFIX "Limes.hashes.unit.")
# cmake-format: on

option (LHASH_BENCH "Build the lhashes benchmarks" ON)

mark_as_advanced (LHASH_BENCH)

if (LHASH_BENCH)

	add_executable (lhashes_benchmarks)

	target_sources (lhashes_benchmarks PRIVATE bench.cpp)

	target_link_libraries (lhashes_benchmarks PRIVATE Catch2::Catch2WithMain limes::lhashes)

	lhash_copy_dlls (lhashes_benchmarks)

	add_custom_target (
		lhashes_bench
		COMMAND lhashes_benchmarks "[!benchmark]" --order rand --verbosity high
		COMMENT "Running lhashes benchmarks..."
		USES_TERMINAL
		SOURCES bench.cpp)

endif ()
