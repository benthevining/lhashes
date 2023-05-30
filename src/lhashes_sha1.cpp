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

#include <cstdint>		// for uint32_t, uint8_t
#include <cstdio>		// for snprintf, size_t
#include <cstring>		// for memcpy, strcat, strcpy
#include <string>		// for basic_string
#include <string_view>	// for string_view
#include <sstream>
#include <iomanip>
#include "lhashes/lhashes_sha1.h"	 // for sha1

namespace limes::hash
{

static constexpr auto BLOCK_INTS  = 16UL;
static constexpr auto BLOCK_BYTES = BLOCK_INTS * 4UL;

static inline void buffer_to_block (const std::string& buffer, std::uint32_t* block) noexcept
{
	for (auto i = 0UL; i < BLOCK_INTS; i++)
	{
		const auto fourI = i * 4UL;

		block[i] = static_cast<std::uint32_t> ((buffer[fourI + 3UL] & 0xff)
											   | (buffer[fourI + 2UL] & 0xff) << 8
											   | (buffer[fourI + 1UL] & 0xff) << 16
											   | (buffer[fourI + 0UL] & 0xff) << 24);
	}
}

[[nodiscard]] static inline std::uint32_t rol (std::uint32_t value, size_t bits) noexcept
{
	return (value << bits) | (value >> (32 - bits));
}

[[nodiscard]] static inline std::uint32_t blk (const std::uint32_t* block, size_t i) noexcept
{
	return rol (block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
}

static inline void R0 (const std::uint32_t* block, std::uint32_t v, std::uint32_t& w, std::uint32_t x, std::uint32_t y, std::uint32_t& z, size_t i) noexcept
{
	z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol (v, 5);
	w = rol (w, 30);
}

static inline void R1 (std::uint32_t* block, std::uint32_t v, std::uint32_t& w, std::uint32_t x, std::uint32_t y, std::uint32_t& z, size_t i) noexcept
{
	block[i] = blk (block, i);
	z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol (v, 5);
	w = rol (w, 30);
}

static inline void R2 (std::uint32_t* block, std::uint32_t v, std::uint32_t& w, std::uint32_t x, std::uint32_t y, std::uint32_t& z, size_t i) noexcept
{
	block[i] = blk (block, i);
	z += (w ^ x ^ y) + block[i] + 0x6ed9eba1 + rol (v, 5);
	w = rol (w, 30);
}

static inline void R3 (std::uint32_t* block, std::uint32_t v, std::uint32_t& w, std::uint32_t x, std::uint32_t y, std::uint32_t& z, size_t i) noexcept
{
	block[i] = blk (block, i);
	z += (((w | x) & y) | (w & x)) + block[i] + 0x8f1bbcdc + rol (v, 5);
	w = rol (w, 30);
}

static inline void R4 (std::uint32_t* block, std::uint32_t v, std::uint32_t& w, std::uint32_t x, std::uint32_t y, std::uint32_t& z, size_t i) noexcept
{
	block[i] = blk (block, i);
	z += (w ^ x ^ y) + block[i] + 0xca62c1d6 + rol (v, 5);
	w = rol (w, 30);
}

static inline void transform (std::uint32_t* digest, std::uint32_t* block, std::uint64_t& transforms) noexcept
{
	auto a = digest[0];
	auto b = digest[1];
	auto c = digest[2];
	auto d = digest[3];
	auto e = digest[4];

	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0 (block, a, b, c, d, e, 0);
	R0 (block, e, a, b, c, d, 1);
	R0 (block, d, e, a, b, c, 2);
	R0 (block, c, d, e, a, b, 3);
	R0 (block, b, c, d, e, a, 4);
	R0 (block, a, b, c, d, e, 5);
	R0 (block, e, a, b, c, d, 6);
	R0 (block, d, e, a, b, c, 7);
	R0 (block, c, d, e, a, b, 8);
	R0 (block, b, c, d, e, a, 9);
	R0 (block, a, b, c, d, e, 10);
	R0 (block, e, a, b, c, d, 11);
	R0 (block, d, e, a, b, c, 12);
	R0 (block, c, d, e, a, b, 13);
	R0 (block, b, c, d, e, a, 14);
	R0 (block, a, b, c, d, e, 15);
	R1 (block, e, a, b, c, d, 0);
	R1 (block, d, e, a, b, c, 1);
	R1 (block, c, d, e, a, b, 2);
	R1 (block, b, c, d, e, a, 3);
	R2 (block, a, b, c, d, e, 4);
	R2 (block, e, a, b, c, d, 5);
	R2 (block, d, e, a, b, c, 6);
	R2 (block, c, d, e, a, b, 7);
	R2 (block, b, c, d, e, a, 8);
	R2 (block, a, b, c, d, e, 9);
	R2 (block, e, a, b, c, d, 10);
	R2 (block, d, e, a, b, c, 11);
	R2 (block, c, d, e, a, b, 12);
	R2 (block, b, c, d, e, a, 13);
	R2 (block, a, b, c, d, e, 14);
	R2 (block, e, a, b, c, d, 15);
	R2 (block, d, e, a, b, c, 0);
	R2 (block, c, d, e, a, b, 1);
	R2 (block, b, c, d, e, a, 2);
	R2 (block, a, b, c, d, e, 3);
	R2 (block, e, a, b, c, d, 4);
	R2 (block, d, e, a, b, c, 5);
	R2 (block, c, d, e, a, b, 6);
	R2 (block, b, c, d, e, a, 7);
	R3 (block, a, b, c, d, e, 8);
	R3 (block, e, a, b, c, d, 9);
	R3 (block, d, e, a, b, c, 10);
	R3 (block, c, d, e, a, b, 11);
	R3 (block, b, c, d, e, a, 12);
	R3 (block, a, b, c, d, e, 13);
	R3 (block, e, a, b, c, d, 14);
	R3 (block, d, e, a, b, c, 15);
	R3 (block, c, d, e, a, b, 0);
	R3 (block, b, c, d, e, a, 1);
	R3 (block, a, b, c, d, e, 2);
	R3 (block, e, a, b, c, d, 3);
	R3 (block, d, e, a, b, c, 4);
	R3 (block, c, d, e, a, b, 5);
	R3 (block, b, c, d, e, a, 6);
	R3 (block, a, b, c, d, e, 7);
	R3 (block, e, a, b, c, d, 8);
	R3 (block, d, e, a, b, c, 9);
	R3 (block, c, d, e, a, b, 10);
	R3 (block, b, c, d, e, a, 11);
	R4 (block, a, b, c, d, e, 12);
	R4 (block, e, a, b, c, d, 13);
	R4 (block, d, e, a, b, c, 14);
	R4 (block, c, d, e, a, b, 15);
	R4 (block, b, c, d, e, a, 0);
	R4 (block, a, b, c, d, e, 1);
	R4 (block, e, a, b, c, d, 2);
	R4 (block, d, e, a, b, c, 3);
	R4 (block, c, d, e, a, b, 4);
	R4 (block, b, c, d, e, a, 5);
	R4 (block, a, b, c, d, e, 6);
	R4 (block, e, a, b, c, d, 7);
	R4 (block, d, e, a, b, c, 8);
	R4 (block, c, d, e, a, b, 9);
	R4 (block, b, c, d, e, a, 10);
	R4 (block, a, b, c, d, e, 11);
	R4 (block, e, a, b, c, d, 12);
	R4 (block, d, e, a, b, c, 13);
	R4 (block, c, d, e, a, b, 14);
	R4 (block, b, c, d, e, a, 15);

	/* Add the working vars back into digest[] */
	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;

	/* Count the number of transformations */
	transforms++;
}

void SHA1::update (const unsigned char* data, std::size_t length)
{
	while (true)
	{
		char sbuf[BLOCK_BYTES] = {};

		const auto count = std::min (length, BLOCK_BYTES - buffer.size());

		std::memcpy (sbuf, data, count);

		buffer.append (sbuf, count);

		if (buffer.size() != BLOCK_BYTES)
			return;

		std::uint32_t block[BLOCK_INTS] = {};

		buffer_to_block (buffer, block);

		transform (digest, block, transforms);

		buffer.clear();
	}
}

std::string SHA1::getHash()
{
	const auto total_bits = (transforms * BLOCK_BYTES + buffer.size()) * 8;

	buffer += static_cast<char> (0x80);

	const auto orig_size = buffer.size();

	while (buffer.size() < BLOCK_BYTES)
		buffer += static_cast<char> (0x00);

	std::uint32_t block[BLOCK_INTS] = {};

	buffer_to_block (buffer, block);

	if (orig_size > BLOCK_BYTES - 8)
	{
		transform (digest, block, transforms);

		for (size_t i = 0; i < BLOCK_INTS - 2; i++)
			block[i] = 0;
	}

	block[BLOCK_INTS - 1] = (std::uint32_t) total_bits;
	block[BLOCK_INTS - 2] = (std::uint32_t) (total_bits >> 32);

	transform (digest, block, transforms);

	std::stringstream result;

	for (size_t i = 0; i < sizeof (digest) / sizeof (digest[0]); i++)
	{
		result << std::hex << std::setfill ('0') << std::setw (8);
		result << digest[i];
	}

	return result.str();
}

std::size_t SHA1::getLengthOfHash() const
{
	return 40UL;
}


std::string sha1 (const char* input, std::size_t length)
{
	SHA1 hasher;

	hasher.update (reinterpret_cast<const unsigned char*> (input), length);	 // NOLINT

	return hasher.getHash();
}

std::string sha1 (std::string_view input)
{
	return sha1 (input.data(), input.length());
}

}  // namespace limes::hash
