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

add_executable (lhash)
add_executable (limes::lhash ALIAS lhash)

set_target_properties (lhash PROPERTIES OUTPUT_NAME lhash DEBUG_POSTFIX -d)

target_sources (lhash PRIVATE main.cpp)

target_link_libraries (lhash PRIVATE limes::lhashes)

if (WIN32)
	add_custom_command (
		TARGET lhash POST_BUILD COMMAND "${CMAKE_COMMAND}" -E copy -t $<TARGET_FILE_DIR:lhash>
										$<TARGET_RUNTIME_DLLS:lhash> USES_TERMINAL
																	 COMMAND_EXPAND_LISTS)
endif ()

include (GNUInstallDirs)

install (TARGETS lhash EXPORT lhashes_cli RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
												  COMPONENT lhashes_cli)

install (
	EXPORT lhashes_cli
	NAMESPACE limes::
	FILE CLITargets.cmake
	DESTINATION "${LHASH_INSTALL_DEST}"
	COMPONENT lhashes_cli_dev)

include (CPackComponent)

cpack_add_component (
	lhashes_cli
	DISPLAY_NAME "Limes hashes CLI tool"
	DESCRIPTION "Limes hashes CLI executable"
	DEPENDS lhashes
	GROUP limes_hashes_cli)

cpack_add_component (
	lhashes_cli_dev
	DISPLAY_NAME "Limes hashes CLI tool (CMake target export files)"
	DESCRIPTION "Limes hashes CLI executable (CMake target export files)"
	DEPENDS lhashes_cli lhashes_dev
	GROUP limes_hashes_cli)

cpack_add_component_group (limes_hashes_cli DISPLAY_NAME "Limes hashes CLI"
						   DESCRIPTION "Limes hashes CLI tool" PARENT_GROUP limes_hashes)

if (LHASH_TESTS)
	# TODO
endif ()
