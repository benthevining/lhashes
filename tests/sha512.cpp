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

TEST_CASE ("SHA512", "[core][hashes]")
{
	namespace hash = limes::hash;

	SECTION ("Hash of empty string")
	{
		hash::SHA512 hasher;

		hasher.update (nullptr, 0UL);

		const auto hashStr = hasher.getHash();

		REQUIRE (hashStr == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

		REQUIRE (hashStr.length() == hasher.getLengthOfHash());
	}

	SECTION ("Hashing other strings")
	{
		REQUIRE (hash::sha512 ("'Twas brillig, and the slithy toves did gyre and gimble in the wabe") == "6b1aedb9513163c75c1dadb6343fa369f3415f19c239a3b153aa923e189d9543dec3bebbd5d9ef9a62d45f34c72de4c984faa0a971a88ec5708164914d086dfe");

		REQUIRE (hash::sha512 ("Hashing is fun") == "5114591634611f95eed6391c8a0a368ec59366b72d1d4151f0cd83751e64fbdaa58d782a84d097a6d46db124d79f94ef08027f0143dfe7fcf063b50ec4b2f56e");
	}

	SECTION ("Invalid UTF-8")
	{
		REQUIRE (hash::sha512 ("\\x80 \\xFF") == "902a577358052809b5c95ae74378511f9a0009a25809e72e2b4fcdcfaf065d5ff38896fb9a71bde760f8d87768ec9a514a5ed9276791574cdc8044bd2500121a");
	}

	SECTION ("Correct type returned by createHasherForType()")
	{
		auto hasher = hash::createHasherForType (hash::Type::sha512);

		REQUIRE (dynamic_cast<hash::SHA512*> (hasher.get()) != nullptr);
	}
}
