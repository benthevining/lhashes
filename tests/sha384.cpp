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

TEST_CASE ("SHA384", "[core][hashes]")
{
	namespace hash = limes::hash;

	SECTION ("Hash of empty string")
	{
		hash::SHA384 hasher;

		hasher.update (nullptr, 0UL);

		const auto hashStr = hasher.getHash();

		REQUIRE (hashStr == "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");

		REQUIRE (hashStr.length() == hasher.getLengthOfHash());
	}

	SECTION ("Hashing other strings")
	{
		REQUIRE (hash::sha384 ("Hello world") == "9203b0c4439fd1e6ae5878866337b7c532acd6d9260150c80318e8ab8c27ce330189f8df94fb890df1d298ff360627e1");

		REQUIRE (hash::sha384 ("I do not like them, Sam I am") == "42c2a145b36b4b31b2084eccb8b2531ed1d9e5441622b6303547a2629c214fd7e6183941a79d7e93c116fee9781b77f3");
	}

	SECTION ("Invalid UTF-8")
	{
		REQUIRE (hash::sha384 ("\\x80 \\xFF") == "0e723b0bc29ca3738244e044a3b74ea5e33b0546ba1982a57420b3d773f42d83e5b3c77b719ef8b2e72c53173c4eca3b");
	}

	SECTION ("Correct type returned by createHasherForType()")
	{
		auto hasher = hash::createHasherForType (hash::Type::sha384);

		REQUIRE (dynamic_cast<hash::SHA384*> (hasher.get()) != nullptr);
	}
}
