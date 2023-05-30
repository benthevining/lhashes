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
	This file defines the hash::SHA384 class.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** A Hasher object that calculates a %SHA384 hash.

	@ingroup limes_hashes
 */
class LHASH_EXPORT SHA384 final : public Hasher
{
public:
	/** Updates the internal state of the hasher with new data. */
	void update (const unsigned char* data, std::size_t length) final;

	/** Retrieves the calculated SHA384 hash value as a string. */
	[[nodiscard]] std::string getHash() final;

	/** Returns 96. */
	[[nodiscard]] std::size_t getLengthOfHash() const final;

private:
	void transform (const unsigned char* message, unsigned block_nb) noexcept;

	static constinit const unsigned SHA384_512_BLOCK_SIZE = (1024 / 8);

	unsigned m_tot_len { 0 };
	unsigned m_len { 0 };

	unsigned char m_block[2 * SHA384_512_BLOCK_SIZE] = {};	// NOLINT

	std::uint64_t m_h[8] = { 0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL };	// NOLINT
};

/** Calculates a SHA384 hash for the given data.

	@ingroup limes_hashes
	@relates SHA384
 */
[[nodiscard]] LHASH_EXPORT std::string sha384 (const char* input, std::size_t length);

/** Calculates a SHA384 hash for the given string.

	@ingroup limes_hashes
	@relates SHA384
 */
[[nodiscard]] LHASH_EXPORT std::string sha384 (std::string_view input);

}  // namespace limes::hash
