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

include_guard (GLOBAL)

set (base_name "limes.hashes.FindPackage.cli")

set (install_dir "${CMAKE_CURRENT_BINARY_DIR}/cli/install_tree")
set (build_dir "${CMAKE_CURRENT_BINARY_DIR}/FindPackage_CLI")

add_test (NAME "${base_name}.install" COMMAND "${CMAKE_COMMAND}" --install "${lhashes_BINARY_DIR}"
											  --config $<CONFIG> --prefix "${install_dir}")

set_tests_properties ("${base_name}.install" PROPERTIES FIXTURES_SETUP
														LimesHashesFindPackageCLIInstall)

# cmake-format: off
add_test (
	NAME "${base_name}.configure"
	COMMAND "${CMAKE_COMMAND}"
		-S "${CMAKE_CURRENT_LIST_DIR}"
		-B "${build_dir}"
		-G "${CMAKE_GENERATOR}"
		-D "CMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
		-D "CMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
		-D "CMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
		-D "CMAKE_PREFIX_PATH=${install_dir}"
		-D "CMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}"
		-D "BUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}")
# cmake-format: on

set_tests_properties (
	"${base_name}.configure" PROPERTIES FIXTURES_REQUIRED LimesHashesFindPackageCLIInstall
										FIXTURES_SETUP LimesHashesFindPackageCLIConfigure)

add_test (NAME "${base_name}.test" COMMAND "${CMAKE_COMMAND}" --build "${build_dir}" --config
										   $<CONFIG> --target test_lhash)

set_tests_properties (
	"${base_name}.test" PROPERTIES FIXTURES_REQUIRED LimesHashesFindPackageCLIConfigure
								   PASS_REGULAR_EXPRESSION 5eb63bbbe01eeed093cb22bb8f5acdc3)

add_test (NAME "${base_name}.clean" COMMAND "${CMAKE_COMMAND}" -E rm -rf "${build_dir}"
											"${install_dir}")

set_tests_properties (
	"${base_name}.clean"
	PROPERTIES FIXTURES_CLEANUP
			   "LimesHashesFindPackageCLIInstall;LimesHashesFindPackageCLIConfigure")
