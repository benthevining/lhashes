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

add_executable (lhashes_cli)

set_target_properties (lhashes_cli PROPERTIES OUTPUT_NAME lhash)

target_sources (lhashes_cli PRIVATE main.cpp)

target_link_libraries (lhashes_cli PRIVATE limes::lhashes)

install (
	TARGETS lhashes_cli
	EXPORT lhashes
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lhashes NAMELINK_COMPONENT lhashes_dev
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lhashes_dev
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT lhashes
	INCLUDES
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

if (LHASH_TESTS)
	# TODO
endif ()
