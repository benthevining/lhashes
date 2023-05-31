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

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <string>
#include <optional>
#include "lhashes/lhashes.h"

// TODO: add --version

void printUsage()
{
	std::cout << "Usage:\n"
			  << "lhash <mode> [<input>]\n"
			  << "If <input> is not specified, lhash will read from stdin.\n"
			  << "Valid modes: md5, sha1, sha224, sha256, sha384, sha512"
			  << std::endl;
}

int main (int argc, char** argv)
{
	if (argc < 2)
	{
		printUsage();
		return EXIT_FAILURE;
	}

	std::string_view mode { argv[1] };

	if (mode == "help" || mode == "Help")
	{
		printUsage();
		return EXIT_SUCCESS;
	}

	using Type = limes::hash::Type;

	const auto type = [mode]() -> std::optional<Type>
	{
		if (mode == "md5" || mode == "MD5")
			return Type::md5;

		if (mode == "sha1" || mode == "SHA1")
			return Type::sha1;

		if (mode == "sha224" || mode == "SHA224")
			return Type::sha224;

		if (mode == "sha256" || mode == "SHA256")
			return Type::sha256;

		if (mode == "sha384" || mode == "SHA384")
			return Type::sha384;

		if (mode == "sha512" || mode == "SHA512")
			return Type::sha512;

		return std::nullopt;
	}();

	if (! type.has_value())
	{
		std::cout << "Unknown mode requested: '" << mode << "'" << std::endl;
		return EXIT_FAILURE;
	}

	const auto input = [argc, argv]() -> std::string
	{
		if (argc > 2)
			return std::string { argv[2] };

		std::string in;

		std::cin >> in;

		return in;
	}();

	std::cout << limes::hash::hash (*type, input) << std::endl;

	return EXIT_SUCCESS;
}
