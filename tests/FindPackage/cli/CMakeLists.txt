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

cmake_minimum_required (VERSION 3.25 FATAL_ERROR)

project (lhashes_findpackage_cli_test VERSION 0.0.1 LANGUAGES CXX)

find_package (lhashes REQUIRED COMPONENTS lhashes_cli_dev)

if (NOT TARGET limes::lhash)
	message (FATAL_ERROR "limes::lhash target does not exist!")
endif ()

add_custom_target (test_lhash COMMAND limes::lhash md5 "hello world")
