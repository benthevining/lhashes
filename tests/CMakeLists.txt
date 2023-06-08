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

limes_get_catch2 ()

add_executable (lhashes_tests)

target_sources (lhashes_tests PRIVATE md5.cpp sha1.cpp sha224.cpp sha256.cpp sha384.cpp sha512.cpp)

limes_configure_test_target (
	lhashes_tests
	BUNDLE_ID Limes.lhashes.tests
	VERSION_MAJOR "${lhashes_VERSION_MAJOR}"
	FULL_VERSION "${lhashes_VERSION}"
	TEST_CATEGORY hashes)

target_link_libraries (lhashes_tests PRIVATE limes::lhashes)

option (LHASH_BENCH "Build the lhashes benchmarks" ON)

mark_as_advanced (LHASH_BENCH)

if (LHASH_BENCH)

	add_executable (lhashes_benchmarks)

	target_sources (lhashes_benchmarks PRIVATE bench.cpp)

	target_link_libraries (lhashes_benchmarks PRIVATE Catch2::Catch2WithMain limes::lhashes)

	limes_configure_benchmark_target (lhashes_benchmarks BENCH_TARGET lhashes_bench
									  LIB_NAME lhashes)

endif ()
