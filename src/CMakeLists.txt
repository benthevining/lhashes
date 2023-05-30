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

target_sources (
	lhashes
	PRIVATE lhashes_common.cpp
			lhashes_hash.cpp
			lhashes_md5.cpp
			lhashes_sha1.cpp
			lhashes_sha224.cpp
			lhashes_sha256.cpp
			lhashes_sha384.cpp
			lhashes_sha512.cpp)
