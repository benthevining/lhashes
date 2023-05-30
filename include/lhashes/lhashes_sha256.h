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
	This file defines the hash::SHA256 class.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** A Hasher object that calculates a %SHA256 hash.

	@ingroup limes_hashes
 */
class LHASH_EXPORT SHA256 final : public Hasher	 // cppcheck-suppress noConstructor
{
public:
	/** Updates the internal state of the hasher with new data. */
	void update (const unsigned char* data, std::size_t length) final;

	/** Retrieves the calculated SHA256 hash value as a string. */
	[[nodiscard]] std::string getHash() final;

	/** Returns 64. */
	[[nodiscard]] std::size_t getLengthOfHash() const final;

private:
	void transform (const unsigned char* message, unsigned block_nb) noexcept;

	static constinit const unsigned SHA224_256_BLOCK_SIZE = (512 / 8);

	unsigned m_len { 0 };
	unsigned m_tot_len { 0 };

	unsigned char m_block[2 * SHA224_256_BLOCK_SIZE] = {};	// NOLINT

	std::uint32_t m_h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };	// NOLINT
};

/** Calculates a SHA256 hash for the given data.

	@ingroup limes_hashes
	@relates SHA256
 */
[[nodiscard]] LHASH_EXPORT std::string sha256 (const char* input, std::size_t length);

/** Calculates a SHA256 hash for the given string.

	@ingroup limes_hashes
	@relates SHA256
 */
[[nodiscard]] LHASH_EXPORT std::string sha256 (std::string_view input);

}  // namespace limes::hash
