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

/** @defgroup limes_hashes limes_hashes
	Basic cryptographic hashes.

	@anchor lib_limes_hashes

	@tableofcontents{HTML,LaTeX,XML}

	@section limes_hashes_overview Overview

	All classes and functions in this module are accessible after linking to the
	\c limes::lhashes library and including \c lhashes.h.

	This library provides utilities for performing various basic cryptographic
	hash functions. The hash functions themselves are treated in an object oriented
	manner, but also provide free functions for quick and easy hashing.

	@section limes_hashes_design Design goals

	This library is object oriented; each hash function is computed by a hasher object
	that implements the \c Hasher base class interface. Addition of new hash algorithms
	is possible by implementing this interface; however, the \c createHasherForType()
	function is not designed to be extensible. Hash algorithm types are stored in an enum,
	not allowing code from outside Limes to add new types dynamically. The overhead in
	this kind of "registry" design seemed to outweigh its benefit here, as this library
	already includes the most common hash algorithms and adding new ones seems like a
	rare need. If you create a new hash algorithm that implements the \c Hasher interface,
	feel free to submit a pull request and it will be added directly to this library.

	The easiest way to compute a hash for some data is with this library's free functions;
	each hash type has a free function (such as \c hash::md5() , \c hash::sha256 , etc),
	and there is also \c hash::createHasherForType() and \c hash::hash() .

	@section limes_hashes_features Features

	This library provides the following hash functions:
	- MD5
	- SHA1
	- SHA224
	- SHA256
	- SHA384
	- SHA512

	@section limes_hashes_examples Examples

	This code prints the MD5 hash of the contents of a file:
	@code{.cpp}
	limes::files::File file { "/my/file.txt" };

	std::cout << limes::hashes::md5 (file.loadAsString());
	@endcode

	@todo CLI tool docs, tests

	@todo HashTable data structure
 */

/** @file
	The main header for the @ref lib_limes_hashes "limes_hashes" library.

	@ingroup limes_hashes
 */

/** @namespace limes::hash
	Cryptographic hash functions.

	This namespace contains all code of the @ref lib_limes_hashes "limes_hashes"
	library.

	@ingroup limes_hashes
 */

#pragma once

// IWYU pragma: begin_exports
#include "lhashes/lhashes_Version.h"
#include "lhashes/lhashes_hash.h"
#include "lhashes/lhashes_md5.h"
#include "lhashes/lhashes_sha1.h"
#include "lhashes/lhashes_sha224.h"
#include "lhashes/lhashes_sha256.h"
#include "lhashes/lhashes_sha384.h"
#include "lhashes/lhashes_sha512.h"
// IWYU pragma: end_exports
