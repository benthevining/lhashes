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

#include <cstddef>		// for size_t
#include <string>		// for string
#include <string_view>	// for string_view
#include <memory>		// for unique_ptr
#include "lhashes/lhashes_Export.h"

/** @file
	This file defines the hash::Hasher class and the \c hash::hash() free functions.

	@ingroup limes_hashes
 */

namespace limes::hash
{

/** @ingroup limes_hashes
	@{
 */

/** Represents a type of hash function that comes with the Limes library.
	@see createHasherForType()
 */
enum class LHASH_EXPORT Type
{
	md5,	 ///< An MD5 hash.
	sha1,	 ///< An SHA1 hash.
	sha224,	 ///< An SHA224 hash.
	sha256,	 ///< An SHA256 hash.
	sha384,	 ///< An SHA384 hash.
	sha512	 ///< An SHA512 hash.
};

/** A base class representing an object that calculates a hash function.

	You should call the \c update() method with any data that needs to be hashed, and then
	call \c getHash() to finalize the internal calculations and retrieve the final hash value.

	You shouldn't call \c update() again after calling \c getHash() .

	You should use this class by either creating one of the hash function-specific supertypes,
	or through \c createHasherForType() , such as:
	@code{.cpp}
	auto hasher = limes::hash::createHasherForType (limes::hash::Type::sha256);

	hasher->update (get_some_data());

	std::cout << hasher->getHash() << std::endl;
	@endcode

	@see MD5, SHA1, SHA224, SHA256, SHA384, SHA512
 */
class LHASH_EXPORT Hasher
{
public:
	/** Destructor. */
	virtual ~Hasher() = default;

	/** @name Appending data to be hashed */
	///@{

	/** Updates the internal state of the hasher with some new data. */
	virtual void update (const unsigned char* input, std::size_t length) = 0;

	virtual void update (std::string_view input);

	///@}

	/** Retrieves the calculated hash value as a string.
		You shouldn't call \c update() again after calling this function.

		@pre \c update() should have been called at least once before calling this function.

		@post \c update() should not be called again after calling this function.

		@returns The hash string for all of the data that has been sent to \c update() . The string
		will be the length returned by \c getLengthOfHash() .
	 */
	[[nodiscard]] virtual std::string getHash() = 0;

	/** Returns the length of a hash string for this algorithm. */
	[[nodiscard]] virtual std::size_t getLengthOfHash() const = 0;
};

/** Creates an appropriate Hasher for the given Type.

	@see hash()
	@relates Hasher
 */
[[nodiscard]] LHASH_EXPORT std::unique_ptr<Hasher> createHasherForType (Type type);

/** Calculates a hash value for the input data using a hasher appropriate for the desired type.

	@see createHasherForType()
	@relates Hasher
 */
[[nodiscard]] LHASH_EXPORT std::string hash (Type type, const char* input, std::size_t length);

/** Calculates a hash value for the input data using a hasher appropriate for the desired type.

	@see createHasherForType()
	@relates Hasher
 */
[[nodiscard]] LHASH_EXPORT std::string hash (Type type, std::string_view input);

/** @}*/

}  // namespace limes::hash
