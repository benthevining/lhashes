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
#include <catch2/catch_test_macros.hpp>

TEST_CASE ("MD5", "[core][hashes]")
{
	namespace hash = limes::hash;

	SECTION ("Hash of empty string")
	{
		hash::MD5 hasher;

		hasher.update (nullptr, 0UL);

		const auto hashStr = hasher.getHash();

		REQUIRE (hashStr == "d41d8cd98f00b204e9800998ecf8427e");

		REQUIRE (hashStr.length() == hasher.getLengthOfHash());
	}

	SECTION ("Hashing other strings")
	{
		REQUIRE (hash::md5 ("Hello world") == "3e25960a79dbc69b674cd4ec67a72c62");

		REQUIRE (hash::md5 ("Sweet dreams are made of this") == "5861e7cec5f1913b3067b283d70a5c2d");

		REQUIRE (hash::md5 ("The quick brown fox jumps over the lazy dog") == "9e107d9d372bb6826bd81d3542a419d6");

		REQUIRE (hash::md5 ("The quick brown fox jumps over the lazy dog.") == "e4d909c290d0fb1ca068ffaddf22cbd0");
	}

	SECTION ("Invalid UTF-8")
	{
		REQUIRE (hash::md5 ("\\x80 \\xFF") == "5744d183216c67db7195a5fb71b12b77");
	}

	SECTION ("Correct type returned by createHasherForType()")
	{
		auto hasher = hash::createHasherForType (hash::Type::md5);

		REQUIRE (dynamic_cast<hash::MD5*> (hasher.get()) != nullptr);
	}
}
