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

#include <string>
#include <string_view>
#include <cstdint>
#include "lhashes/lhashes_Export.h"
#include "lhashes/lhashes_hash.h"

/** @file
	This file defines the hash::MD5 class.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** A Hasher object that calculates an %MD5 hash.

	@note %MD5 is considered to be broken and insecure, so shouldn't be used for security-critical
	purposes in new applications, but is provided here for backwards compatibility.

	@ingroup limes_hashes
 */
class LHASH_EXPORT MD5 final : public Hasher  // cppcheck-suppress noConstructor
{
public:
	/** Updates the internal state of the hasher with new data. */
	void update (const unsigned char* input, std::size_t length) final;

	/** Retrieves the calculated MD5 hash value as a string. */
	[[nodiscard]] std::string getHash() final;

	/** Returns 32. */
	[[nodiscard]] std::size_t getLengthOfHash() const final;

private:
	void transform (const std::uint8_t* block) noexcept;

	static constexpr auto blocksize = 64;

	std::uint8_t  buffer[blocksize] = {};
	std::uint32_t count[2]			= { 0, 0 };
	std::uint32_t state[4]			= { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	std::uint8_t  digest[16]		= {};
};

/** Calculates an MD5 hash for the given data.

	@ingroup limes_hashes
	@relates MD5
 */
[[nodiscard]] LHASH_EXPORT std::string md5 (const char* input, std::size_t length);

/** Calculates an MD5 hash for the given string.

	@ingroup limes_hashes
	@relates MD5
 */
[[nodiscard]] LHASH_EXPORT std::string md5 (std::string_view input);

}  // namespace limes::hash
