/*
 * ======================================================================================
 *  __    ____  __  __  ____  ___
 * (  )  (_  _)(  \/  )( ___)/ __)
 *  )(__  _)(_  )    (  )__) \__ \
 * (____)(____)(_/\/\_)(____)(___/
 *
 *  This file is part of the Limes open source library and is licensed under the terms of the GNU Public License.
 *
 *  Commercial licenses are available; contact the maintainers at ben.the.vining@gmail.com to inquire for details.
 *
 * ======================================================================================
 */

#include "lhashes/lhashes.h"
#include <catch2/catch_all.hpp>

#define TAGS "[math][hashes][!benchmark]"

namespace hash = limes::hash;

static constexpr auto input = "The quick brown fox jumped over the lazy dog.";

TEST_CASE ("MD5", TAGS)
{
	BENCHMARK ("MD5")
	{
		return hash::md5 (input);
	};
}

TEST_CASE ("SHA1", TAGS)
{
	BENCHMARK ("SHA1")
	{
		return hash::sha1 (input);
	};
}

TEST_CASE ("SHA224", TAGS)
{
	BENCHMARK ("SHA224")
	{
		return hash::sha224 (input);
	};
}

TEST_CASE ("SHA256", TAGS)
{
	BENCHMARK ("SHA256")
	{
		return hash::sha256 (input);
	};
}

TEST_CASE ("SHA384", TAGS)
{
	BENCHMARK ("SHA384")
	{
		return hash::sha384 (input);
	};
}

TEST_CASE ("SHA512", TAGS)
{
	BENCHMARK ("SHA512")
	{
		return hash::sha512 (input);
	};
}

#undef TAGS
