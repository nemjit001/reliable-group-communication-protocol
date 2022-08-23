# Reliable Group Communication Protocol (RGCP)

Designed and implemented as a Bachelor's Thesis for the VU Amsterdam.

## Installing the library

The library can be installed by setting up the CMake project and using the
generated Makefile.

### Setting up the CMake project

To set up the CMake project for a "Release" build, the following command
can be run:

```bash
$ cmake . -D CMAKE_BUILD_TYPE=Release
```

If the CMake project is set up successfully, the library can be installed
by using the generated Makefile.

### Installation using Make

The library can be installed by running the following make command:

```bash
$ sudo make install
```

The RGCP library is installed in the GNU install directories. After
installation the library can be linked and used according to the
[documentation](documentation/RGCPDocs.md).

## Running tests

To build and run the tests for the RGCP library, enter the `test` directory
and build the CMake project using the following command:

```bash
$ cmake .
```

Ensure that a middleware service is running on `localhost:8000` with default parameters before testing.

All tests can be built and run using the following Make command:

```bash
$ make all test
```

## Author

Tijmen Menno Verhoef
