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
#include <array>
#include "lhashes/lhashes_Export.h"
#include "lhashes/lhashes_hash.h"

/** @file
	This file defines the hash::SHA224 class.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** A Hasher object that calculates a %SHA224 hash.

	@ingroup limes_hashes
 */
class LHASH_EXPORT SHA224 final : public Hasher	 // cppcheck-suppress noConstructor
{
public:
	/** Updates the internal state of the hasher with new data. */
	void update (const unsigned char* message, std::size_t len) final;

	/** Retrieves the calculated SHA224 hash value as a string. */
	[[nodiscard]] std::string getHash() final;

	/** Returns 56. */
	[[nodiscard]] std::size_t getLengthOfHash() const final;

private:
	void transform (const unsigned char* message, unsigned block_nb) noexcept;

	static constexpr auto blocksize = 512 / 8;

	unsigned m_len { 0u };
	unsigned m_tot_len { 0u };

	unsigned char m_block[2 * blocksize] = {};

	std::uint32_t m_h[8] { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };
};

/** Calculates a SHA224 hash for the given data.

	@ingroup limes_hashes
	@relates SHA224
 */
[[nodiscard]] LHASH_EXPORT std::string sha224 (const char* input, std::size_t length);

/** Calculates a SHA224 hash for the given data.

	@ingroup limes_hashes
	@relates SHA224
 */
[[nodiscard]] LHASH_EXPORT std::string sha224 (std::string_view input);

}  // namespace limes::hash
