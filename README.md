
# libkazv

libkazv is a matrix client sdk built upon [lager](https://github.com/arximboldi/lager)
and the value-oriented design it enables.

# Build and Use

You can build libkazv through the standard CMake process:

```
mkdir -pv build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/path/to/prefix
make install
```

libkazv offers the following CMake options:

- `libkazv_BUILD_TESTS`: boolean value to specify whether to build tests
- `libkazv_BUILD_EXAMPLES`: boolean value to specify whether to build examples
- `libkazv_OUTPUT_LEVEL`: integral value from 0 to 100 to determine what kinds
  of logs are shown. Setting to 100 makes libkazv output the most debug
  information.
- `libkazv_INSTALL_HEADERS`: boolean value to determine whether to install
  libkazv's headers. This is by default set to OFF when libkazv is built
  as a subproject.

libkazv can be incorporated into your project using CMake `FetchContent()`.
It has two libraries you can link to:

- `libkazv::kazv` is the one that contains API call definitions
  and client logic. It does not, however, define how the jobs are
  fetched.
- `libkazv::kazvjob` is a tiny library that provides async
  and network fetching functionalities. There is one class
  `CprJobHandler` that implements `JobInterface` in `kazv`.
  You can link your program to `kazvjob` or make up another
  job handler using what you choose as async and network
  libraries. To switch from one job handler to another,
  you only need to change one or two lines in your program.


# Acknowledgement

libkazv uses [gtad](https://github.com/KitsuneRal/gtad) to generate the API
definitions it needed. The source of the Matrix API is
[https://github.com/matrix-org/matrix-doc](https://github.com/matrix-org/matrix-doc)
. The gtad configuration files and json/query serializing used in libkazv are
adapted from the ones in [libQuotient](https://github.com/quotient-im/libQuotient).
libQuotient is released under GNU LGPL v2.1. The changes in said files
in libkazv compared to libQuotient's are:

- Get rid of the `avoidCopy` and `moveOnly` markers
- Use data types from `immer` and `std` instead of Qt
- Use `nlohmann::json` instead of Qt's JSON library