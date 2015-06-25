# HCS #

HCS is a library implementing a number of partially homomorphic
cryptosystems. The following schemes are currently implemented:

* Paillier
* Damgard-Jurik
* El-Gamal

These schemes are designed to have a simple API to use, whilst being
fast and secure (hopefully). There is a requirement on the GMP bignum
library, and some knowledge regarding the datatypes is required, as
the types are not currently wrapped in some above layer. To build this library,
cmake 3.0 or greater is required.

## To install
    git clone https://github.com/Tiehuis/libhcs.git
    cmake .
    make
    sudo make install

To uninstall, type
    sudo xargs rm < install_manifest.txt

## Things to do

Ideally, once finished we should have:

* Clear documentation using doxygen
* A number of homomorphic schemes, plus some threshold variants
* Some example applications which demonstrate usability of these libraries
