# ======================================================================================
#  __    ____  __  __  ____  ___
# (  )  (_  _)(  \/  )( ___)/ __)
#  )(__  _)(_  )    (  )__) \__ \
# (____)(____)(_/\/\_)(____)(___/
#
#  This file is part of the Limes open source library and is licensed under the terms of the GNU Public License.
#
#  Commercial licenses are available; contact the maintainers at ben.the.vining@gmail.com to inquire for details.
#
# ======================================================================================

set (base_name limes.hashes.cli)

set (input_string "It was the best of times, it was the worst of times.")

#

add_test (NAME "${base_name}.MD5" COMMAND limes::lhash md5 "${input_string}")

set_tests_properties ("${base_name}.MD5" PROPERTIES PASS_REGULAR_EXPRESSION
                                                    "2b6f3903029659f55174170251787336")

#

add_test (NAME "${base_name}.SHA1" COMMAND limes::lhash sha1 "${input_string}")

set_tests_properties ("${base_name}.SHA1" PROPERTIES PASS_REGULAR_EXPRESSION
                                                     "74dbcda6019c2b1e1507009ecc2940b2f3c8eb0d")

#

add_test (NAME "${base_name}.SHA224" COMMAND limes::lhash sha224 "${input_string}")

set_tests_properties (
    "${base_name}.SHA224" PROPERTIES PASS_REGULAR_EXPRESSION
                                     "75b7ebb10247fa7d3023ce45c02502c035e1954f580b4e76aa9416c5")

#

add_test (NAME "${base_name}.SHA256" COMMAND limes::lhash sha256 "${input_string}")

set_tests_properties (
    "${base_name}.SHA256"
    PROPERTIES PASS_REGULAR_EXPRESSION
               "38d141b35057bbb691b9756c20a6c31a0ab0bbf2076538a7fb6d9ee8835096d7")

#

add_test (NAME "${base_name}.SHA384" COMMAND limes::lhash sha384 "${input_string}")

set_tests_properties (
    "${base_name}.SHA384"
    PROPERTIES
        PASS_REGULAR_EXPRESSION
        "b1877e6be11ab4dcfdc91813476dfcbe7e724fe83622663722c9dd22c6c237a67c2de6ca2429154a01074d7bd5559919"
    )

#

add_test (NAME "${base_name}.SHA512" COMMAND limes::lhash sha512 "${input_string}")

set_tests_properties (
    "${base_name}.SHA512"
    PROPERTIES
        PASS_REGULAR_EXPRESSION
        "c86c1bfea656d1dd8accc4faf4d2788f631f5c3f58c7bcafdd2266f26115c8c8318b750aec2bbed3e4bd2f038af17de4dd35192f8192410bd25371b51fee653a"
    )
