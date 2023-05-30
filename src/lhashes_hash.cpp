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

#include <string_view>
#include <string>
#include "lhashes/lhashes_hash.h"
#include "lhashes/lhashes_md5.h"
#include "lhashes/lhashes_sha1.h"
#include "lhashes/lhashes_sha224.h"
#include "lhashes/lhashes_sha256.h"
#include "lhashes/lhashes_sha384.h"
#include "lhashes/lhashes_sha512.h"

namespace limes::hash
{

void Hasher::update (std::string_view input)
{
	update (reinterpret_cast<const unsigned char*> (input.data()),
			static_cast<std::size_t> (input.length()));
}

std::unique_ptr<Hasher> createHasherForType (Type type)
{
	switch (type)
	{
		case (Type::md5) : return std::make_unique<MD5>();
		case (Type::sha1) : return std::make_unique<SHA1>();
		case (Type::sha224) : return std::make_unique<SHA224>();
		case (Type::sha256) : return std::make_unique<SHA256>();
		case (Type::sha384) : return std::make_unique<SHA384>();
		case (Type::sha512) : return std::make_unique<SHA512>();
		default : return nullptr;
	}
}


std::string hash (Type type, const char* input, std::size_t length)
{
	// NOTE: call the hash functions directly instead of using
	// createHasherForType() to allow the underlying hasher
	// objects to live on the stack, instead of always incurring
	// a heap allocation with std::make_unique

	switch (type)
	{
		case (Type::md5) : return md5 (input, length);
		case (Type::sha1) : return sha1 (input, length);
		case (Type::sha224) : return sha224 (input, length);
		case (Type::sha256) : return sha256 (input, length);
		case (Type::sha384) : return sha384 (input, length);
		case (Type::sha512) : return sha512 (input, length);
		default : return {};
	}
}

std::string hash (Type type, std::string_view input)
{
	return hash (type, input.data(), input.length());
}

}  // namespace limes::hash
