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

TEST_CASE ("SHA1", "[core][hashes]")
{
	namespace hash = limes::hash;

	SECTION ("Hash of empty string")
	{
		hash::SHA1 hasher;

		hasher.update (nullptr, 0UL);

		const auto hashStr = hasher.getHash();

		REQUIRE (hashStr == "da39a3ee5e6b4b0d3255bfef95601890afd80709");

		REQUIRE (hashStr.length() == hasher.getLengthOfHash());
	}

	SECTION ("Hashing other strings")
	{
		REQUIRE (hash::sha1 ("Good morning world, and all who inhabit it!") == "a194dbaab2ac016d1a5ef7ef5c08154bd383a6cf");

		REQUIRE (hash::sha1 ("I'm ready, I'm ready, I'm ready!") == "931e720534bc1ca4b89b14ecd391a3f150a38ddc");
	}

	SECTION ("Invalid UTF-8")
	{
		REQUIRE (hash::sha1 ("\\x80 \\xFF") == "43ca50ba21d56639158494135e26cc4c02d73e09");
	}

	SECTION ("Correct type returned by createHasherForType()")
	{
		auto hasher = hash::createHasherForType (hash::Type::sha1);

		REQUIRE (dynamic_cast<hash::SHA1*> (hasher.get()) != nullptr);
	}
}
