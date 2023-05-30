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

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include "lhashes/lhashes_Export.h"
#include "lhashes/lhashes_hash.h"

/** @file
	This file defines the hash::SHA1 class.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** A Hasher object that calculates a %SHA1 hash.

	@note %SHA1 is considered to be insecure and shouldn't be used for security-critical
	purposes in new projects, but is provided here for backwards compatibility.

	@ingroup limes_hashes
 */
class LHASH_EXPORT SHA1 final : public Hasher  // cppcheck-suppress noConstructor
{
public:
	/** Updates the internal state of the hasher with new data. */
	void update (const unsigned char* data, std::size_t length) final;

	/** Retrieves the calculated SHA1 hash value as a string. */
	[[nodiscard]] std::string getHash() final;

	/** Returns 40. */
	[[nodiscard]] std::size_t getLengthOfHash() const final;

private:
	std::uint32_t digest[5] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

	std::string buffer;

	std::uint64_t transforms { 0 };
};

/** Calculates a SHA1 hash for the given data.

	@ingroup limes_hashes
	@relates SHA1
 */
[[nodiscard]] LHASH_EXPORT std::string sha1 (const char* input, std::size_t length);

/** Calculates a SHA1 hash for the given string.

	@ingroup limes_hashes
	@relates SHA1
 */
[[nodiscard]] LHASH_EXPORT std::string sha1 (std::string_view input);

}  // namespace limes::hash
