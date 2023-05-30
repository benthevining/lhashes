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

TEST_CASE ("SHA256", "[core][hashes]")
{
	namespace hash = limes::hash;

	SECTION ("Hash of empty string")
	{
		hash::SHA256 hasher;

		hasher.update (nullptr, 0UL);

		const auto hashStr = hasher.getHash();

		REQUIRE (hashStr == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

		REQUIRE (hashStr.length() == hasher.getLengthOfHash());
	}

	SECTION ("Hashing other strings")
	{
		REQUIRE (hash::sha256 ("Good night moon") == "4b28bd4b80da49612eaa04ad68b3107ad14b4c380f9bf5ac008d4df31eedf52b");

		REQUIRE (hash::sha256 ("SHA256 is a cryptographic hash function") == "ed54afb24bee25613c770cc55a71cac0129aab13455d603182bc01f795b43440");

		REQUIRE (hash::sha256 ("The quick brown fox jumps over the lazy dog") == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

		REQUIRE (hash::sha256 ("The quick brown fox jumps over the lazy dog.") == "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c");
	}

	SECTION ("Invalid UTF-8")
	{
		REQUIRE (hash::sha256 ("\\x80 \\xFF") == "7227f8fd827f54c9e1c078bc8ecb8cfcf4d3b370bdab113d46f16259902373ed");
	}

	SECTION ("Correct type returned by createHasherForType()")
	{
		auto hasher = hash::createHasherForType (hash::Type::sha256);

		REQUIRE (dynamic_cast<hash::SHA256*> (hasher.get()) != nullptr);
	}
}
