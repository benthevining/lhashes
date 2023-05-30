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

TEST_CASE ("SHA224", "[core][hashes]")
{
	namespace hash = limes::hash;

	SECTION ("Hash of empty string")
	{
		hash::SHA224 hasher;

		hasher.update (nullptr, 0UL);

		const auto hashStr = hasher.getHash();

		REQUIRE (hashStr == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

		REQUIRE (hashStr.length() == hasher.getLengthOfHash());
	}

	SECTION ("Hashing other strings")
	{
		REQUIRE (hash::sha224 ("Hello world") == "ac230f15fcae7f77d8f76e99adf45864a1c6f800655da78dea956112");

		REQUIRE (hash::sha224 ("The quick brown fox jumps over the lazy dog") == "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
	}

	SECTION ("Invalid UTF-8")
	{
		REQUIRE (hash::sha224 ("\\x80 \\xFF") == "fe827ce8dcf54f42eaf36912d12079e4f8623735f45ea211847a18b2");
	}

	SECTION ("Correct type returned by createHasherForType()")
	{
		auto hasher = hash::createHasherForType (hash::Type::sha224);

		REQUIRE (dynamic_cast<hash::SHA224*> (hasher.get()) != nullptr);
	}
}
