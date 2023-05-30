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
	This file defines the hash::SHA512 class.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** A Hasher object that calculates a %SHA512 hash.

	@ingroup limes_hashes
 */
class LHASH_EXPORT SHA512 final : public Hasher
{
public:
	/** Updates the internal state of the hasher with new data. */
	void update (const unsigned char* data, std::size_t length) final;

	/** Retrieves the calculated SHA512 hash value as a string. */
	[[nodiscard]] std::string getHash() final;

	/** Returns 128. */
	[[nodiscard]] std::size_t getLengthOfHash() const final;

private:
	void transform (const unsigned char* message, unsigned block_nb) noexcept;

	static constinit const unsigned SHA384_512_BLOCK_SIZE = (1024 / 8);

	unsigned m_tot_len { 0 };
	unsigned m_len { 0 };

	unsigned char m_block[2 * SHA384_512_BLOCK_SIZE] = {};

	std::uint64_t m_h[8] = { 0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL };
};

/** Calculates a SHA512 hash for the given data.

	@ingroup limes_hashes
	@relates SHA512
 */
[[nodiscard]] LHASH_EXPORT std::string sha512 (const char* input, std::size_t length);

/** Calculates a SHA512 hash for the given string.

	@ingroup limes_hashes
	@relates SHA512
 */
[[nodiscard]] LHASH_EXPORT std::string sha512 (std::string_view input);

}  // namespace limes::hash
