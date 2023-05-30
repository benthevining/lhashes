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

#include <algorithm>  // for min
#include <cstdint>	  // for uint32_t, uint8_t
#include <cstdio>	  // for sprintf, size_t
#include <cstring>	  // for memcpy, memset
#include <cstddef>
#include <string>		// for basic_string
#include <string_view>	// for string_view
#include "lhashes/lhashes_sha224.h"
#include "lhashes/lhashes_common.h"

namespace limes::hash
{

void SHA224::update (const unsigned char* message, std::size_t len)
{
	const auto tmp_len = blocksize - m_len;
	auto	   rem_len = len < tmp_len ? len : tmp_len;

	std::memcpy (&m_block[m_len], message, rem_len);  // NOLINT

	if (m_len + len < blocksize)
	{
		m_len += len;
		return;
	}

	const auto new_len	= len - rem_len;
	const auto block_nb = new_len / blocksize;

	const auto* const shifted_message = message + rem_len;

	transform (m_block, 1u);
	transform (shifted_message, static_cast<unsigned> (block_nb));

	rem_len = new_len % blocksize;

	std::memcpy (m_block, &shifted_message[block_nb << 6], rem_len);

	m_len = static_cast<decltype (m_len)> (rem_len);

	m_tot_len += (block_nb + 1) << 6;
}

void SHA224::transform (const unsigned char* message, unsigned block_nb) noexcept
{
	std::uint32_t w[64] = {};  // NOLINT
	std::uint32_t wv[8] = {};  // NOLINT
	std::uint32_t t1, t2;	   // NOLINT

	const unsigned char* sub_block { nullptr };

	for (auto i = 0; i < static_cast<int> (block_nb); ++i)
	{
		sub_block = message + static_cast<std::ptrdiff_t> (i << 6);

		for (auto j = 0; j < 16; j++)
			util::pack32 (&sub_block[j << 2], w[j]);  // NOLINT

		for (auto j = 16; j < 64; j++)
			w[j] = util::sha256_F4 (w[j - 2]) + w[j - 7] + util::sha256_F3 (w[j - 15]) + w[j - 16];	 // NOLINT

		for (auto j = 0; j < 8; j++)
			wv[j] = m_h[j];	 // NOLINT

		for (auto j = 0; j < 64; j++)
		{
			t1	  = wv[7] + util::sha256_F2 (wv[4]) + util::ch (wv[4], wv[5], wv[6]) + util::sha256_k[j] + w[j];  // NOLINT
			t2	  = util::sha256_F1 (wv[0]) + util::maj (wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}

		for (auto j = 0; j < 8; j++)
			m_h[j] += wv[j];  // NOLINT
	}
}

std::string SHA224::getHash()
{
	const auto block_nb = 1 + static_cast<int> ((blocksize - 9) < (m_len % blocksize));
	const auto len_b	= (m_tot_len + m_len) << 3;
	const auto pm_len	= block_nb << 6;

	std::memset (m_block + m_len, 0,
				 static_cast<std::size_t> (pm_len - static_cast<decltype (pm_len)> (m_len)));

	m_block[m_len] = 0x80;	// NOLINT

	util::unpack32 (len_b, m_block + pm_len - 4);

	transform (m_block, static_cast<unsigned> (block_nb));

	static constexpr auto digestSize = 224 / 8;

	unsigned char digest[digestSize] = {};	// NOLINT

	std::memset (digest, 0, digestSize);

	for (auto i = 0; i < 7; i++)
		util::unpack32 (m_h[i], &digest[i << 2]);  // NOLINT

	char buf[2 * digestSize + 1] = {};	// NOLINT

	buf[2 * digestSize] = 0;  // NOLINT

	for (auto i = 0; i < digestSize; i++)
		std::sprintf (buf + static_cast<std::ptrdiff_t> (i * 2), "%02x", digest[i]);  // NOLINT

	return std::string { buf };
}

std::size_t SHA224::getLengthOfHash() const
{
	return 56UL;
}

std::string sha224 (const char* input, std::size_t length)
{
	SHA224 hasher;

	hasher.update (reinterpret_cast<const unsigned char*> (input), length);	 // NOLINT

	return hasher.getHash();
}

std::string sha224 (std::string_view input)
{
	return sha224 (input.data(), input.length());
}

}  // namespace limes::hash
