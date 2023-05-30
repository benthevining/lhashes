# lhashes

[![CI](https://github.com/benthevining/lhashes/actions/workflows/ci.yml/badge.svg)](https://github.com/benthevining/lhashes/actions/workflows/ci.yml) [![Build docs](https://github.com/benthevining/lhashes/actions/workflows/docs.yml/badge.svg)](https://github.com/benthevining/lhashes/actions/workflows/docs.yml) [![pre-commit.ci status](https://results.pre-commit.ci/badge/github/benthevining/lhashes/main.svg)](https://results.pre-commit.ci/latest/github/benthevining/lhashes/main)

C++ hashing library

## Features

This library provides basic cryptographic hash functions.

## Portability

This library is tested on Mac, Windows, and Linux (with GCC, Clang, and MSVC), as well as cross-compiled
for iOS, tvOS, watchOS, and Emscripten (WebAssembly).

## Building

This library is built with CMake. CMake presets are provided for each of the toolchains we target. This
library supports being added to other CMake projects via `find_package()`, `FetchContent`, or a plain
`add_subdirectory()`. In all cases, you should link against the target `limes::lhashes` and include
the main header this way:
```cpp
#include <lhashes/lhashes.h>
```
All of this library's headers can be individually included, but including `lhashes.h` is the easiest
way to bring in the entire library.

## Links

[CDash testing dashboard](https://my.cdash.org/index.php?project=lhashes)

[Documentation](https://benthevining.github.io/lhashes/)
