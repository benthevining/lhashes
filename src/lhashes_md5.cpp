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

#include <cstring>
#include <cstddef>
#include "lhashes/lhashes_md5.h"

namespace limes::hash
{

static inline void decode (std::uint32_t* output, const std::uint8_t* input, size_t len) noexcept
{
	for (auto i = 0UL, j = 0UL; j < len; i++, j += 4UL)
		output[i] = static_cast<std::uint32_t> (input[j]) | (static_cast<std::uint32_t> (input[j + 1]) << 8) | (static_cast<std::uint32_t> (input[j + 2]) << 16) | (static_cast<std::uint32_t> (input[j + 3]) << 24);
}

[[nodiscard]] static inline std::uint32_t F (std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
{
	return (x & y) | (~x & z);
}

[[nodiscard]] static inline std::uint32_t G (std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
{
	return (x & z) | (y & ~z);
}

[[nodiscard]] static inline std::uint32_t H (std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
{
	return x ^ y ^ z;
}

[[nodiscard]] static inline std::uint32_t I (std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
{
	return y ^ (x | ~z);
}

[[nodiscard]] static inline std::uint32_t rotate_left (std::uint32_t x, std::uint32_t n) noexcept
{
	return (x << n) | (x >> (32 - n));
}

static inline void FF (std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, std::uint32_t s, std::uint32_t ac) noexcept
{
	a = rotate_left (a + F (b, c, d) + x + ac, s) + b;
}

static inline void GG (std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, std::uint32_t s, std::uint32_t ac) noexcept
{
	a = rotate_left (a + G (b, c, d) + x + ac, s) + b;
}

static inline void HH (std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, std::uint32_t s, std::uint32_t ac) noexcept
{
	a = rotate_left (a + H (b, c, d) + x + ac, s) + b;
}

static inline void II (std::uint32_t& a, std::uint32_t b, std::uint32_t c, std::uint32_t d, std::uint32_t x, std::uint32_t s, std::uint32_t ac) noexcept
{
	a = rotate_left (a + I (b, c, d) + x + ac, s) + b;
}

void MD5::transform (const std::uint8_t* block) noexcept
{
	auto a = state[0];
	auto b = state[1];
	auto c = state[2];
	auto d = state[3];

	std::uint32_t x[16];

	decode (x, block, blocksize);

	static constexpr auto S11 = 7;
	static constexpr auto S12 = 12;
	static constexpr auto S13 = 17;
	static constexpr auto S14 = 22;
	static constexpr auto S21 = 5;
	static constexpr auto S22 = 9;
	static constexpr auto S23 = 14;
	static constexpr auto S24 = 20;
	static constexpr auto S31 = 4;
	static constexpr auto S32 = 11;
	static constexpr auto S33 = 16;
	static constexpr auto S34 = 23;
	static constexpr auto S41 = 6;
	static constexpr auto S42 = 10;
	static constexpr auto S43 = 15;
	static constexpr auto S44 = 21;

	/* Round 1 */
	FF (a, b, c, d, x[0], S11, 0xd76aa478);	 /* 1 */
	FF (d, a, b, c, x[1], S12, 0xe8c7b756);	 /* 2 */
	FF (c, d, a, b, x[2], S13, 0x242070db);	 /* 3 */
	FF (b, c, d, a, x[3], S14, 0xc1bdceee);	 /* 4 */
	FF (a, b, c, d, x[4], S11, 0xf57c0faf);	 /* 5 */
	FF (d, a, b, c, x[5], S12, 0x4787c62a);	 /* 6 */
	FF (c, d, a, b, x[6], S13, 0xa8304613);	 /* 7 */
	FF (b, c, d, a, x[7], S14, 0xfd469501);	 /* 8 */
	FF (a, b, c, d, x[8], S11, 0x698098d8);	 /* 9 */
	FF (d, a, b, c, x[9], S12, 0x8b44f7af);	 /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[1], S21, 0xf61e2562);	 /* 17 */
	GG (d, a, b, c, x[6], S22, 0xc040b340);	 /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[0], S24, 0xe9b6c7aa);	 /* 20 */
	GG (a, b, c, d, x[5], S21, 0xd62f105d);	 /* 21 */
	GG (d, a, b, c, x[10], S22, 0x2441453);	 /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[4], S24, 0xe7d3fbc8);	 /* 24 */
	GG (a, b, c, d, x[9], S21, 0x21e1cde6);	 /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[3], S23, 0xf4d50d87);	 /* 27 */
	GG (b, c, d, a, x[8], S24, 0x455a14ed);	 /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[2], S22, 0xfcefa3f8);	 /* 30 */
	GG (c, d, a, b, x[7], S23, 0x676f02d9);	 /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[5], S31, 0xfffa3942);	 /* 33 */
	HH (d, a, b, c, x[8], S32, 0x8771f681);	 /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[1], S31, 0xa4beea44);	 /* 37 */
	HH (d, a, b, c, x[4], S32, 0x4bdecfa9);	 /* 38 */
	HH (c, d, a, b, x[7], S33, 0xf6bb4b60);	 /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[0], S32, 0xeaa127fa);	 /* 42 */
	HH (c, d, a, b, x[3], S33, 0xd4ef3085);	 /* 43 */
	HH (b, c, d, a, x[6], S34, 0x4881d05);	 /* 44 */
	HH (a, b, c, d, x[9], S31, 0xd9d4d039);	 /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[2], S34, 0xc4ac5665);	 /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[0], S41, 0xf4292244);	 /* 49 */
	II (d, a, b, c, x[7], S42, 0x432aff97);	 /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[5], S44, 0xfc93a039);	 /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[3], S42, 0x8f0ccc92);	 /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[1], S44, 0x85845dd1);	 /* 56 */
	II (a, b, c, d, x[8], S41, 0x6fa87e4f);	 /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[6], S43, 0xa3014314);	 /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[4], S41, 0xf7537e82);	 /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[2], S43, 0x2ad7d2bb);	 /* 63 */
	II (b, c, d, a, x[9], S44, 0xeb86d391);	 /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

void MD5::update (const unsigned char* input, std::size_t length)
{
	auto index = count[0] / 8 % blocksize;

	if ((count[0] += static_cast<std::uint32_t> (length << 3UL)) < static_cast<std::uint32_t> (length << 3UL))
		count[1]++;

	count[1] += static_cast<std::uint32_t> (length >> 29UL);

	const auto firstpart = 64 - index;

	auto i = 0UL;

	if (length >= firstpart)
	{
		std::memcpy (&buffer[index], input, firstpart);

		transform (buffer);

		for (i = firstpart;
			 i + static_cast<std::size_t> (blocksize) <= length;
			 i += blocksize)
		{
			transform (&input[i]);
		}

		index = 0;
	}

	std::memcpy (&buffer[index], &input[i], length - i);
}

static inline void encode (std::uint8_t* output, const std::uint32_t* input, size_t len) noexcept
{
	for (auto i = 0UL, j = 0UL; j < len; i++, j += 4UL)
	{
		output[j]	  = input[i] & 0xff;
		output[j + 1] = (input[i] >> 8) & 0xff;
		output[j + 2] = (input[i] >> 16) & 0xff;
		output[j + 3] = (input[i] >> 24) & 0xff;
	}
}

std::string MD5::getHash()
{
	static unsigned char padding[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	unsigned char bits[8] = {};

	encode (bits, count, 8);

	const auto index  = count[0] / 8 % 64;
	const auto padLen = (index < 56) ? (56 - index) : (120 - index);

	update (padding, padLen);
	update (bits, 8);

	encode (digest, state, 16);

	std::memset (buffer, 0, sizeof buffer);
	std::memset (count, 0, sizeof count);

	char buf[33] = {};

	for (auto i = 0; i < 16; i++)
	{
		sprintf (buf + static_cast<std::ptrdiff_t> (i * 2),	 // NOLINT
				 "%02x",
				 digest[i]);
	}

	buf[32] = 0;

	return std::string { buf };
}

std::size_t MD5::getLengthOfHash() const
{
	return 32UL;
}

std::string md5 (const char* input, std::size_t length)
{
	MD5 hasher;

	hasher.update (reinterpret_cast<const unsigned char*> (input), length);	 // NOLINT

	return hasher.getHash();
}

std::string md5 (std::string_view input)
{
	return md5 (input.data(), input.length());
}

}  // namespace limes::hash
