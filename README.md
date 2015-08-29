# libhcs #

libhcs is a C library implementing a number of partially homormophic encryption
schemes. Currently the following are implemented:

* Paillier
* Damgard-Jurik
* El-Gamal

Focus is on the Paillier implementations, with proofs and the leading work
being done on this. A simple C++ interface is also provided, however, it may
lag behind the C interface, and is primarily for convenience in writing unit
tests at this stage.

In particular, we focus on the Threshold Variant of the Paillier
cryptosystem.

## Dependencies

There is a dependency on the [GMP](https://gmplib.org/) library. This also
means that some familiarity with this library is required. A useful manual can
be found on the website linked above.

The [CMake](http://www.cmake.org/) build system is used to generate the
required build files. CMake 2.8 or greater is currently required.

The [Catch](https://github.com/philsquared/Catch) unit testing framework is
used to test all functions. This however is packaged in this repository, so it
is not required to obtain yourself.

To obtain the needed requirements on Ubuntu 15.10, one may run the following
command:

    sudo apt-get install libgmp-dev cmake

## Installation

Assuming all dependencies are on your system, the following will work on a
typical linux system.

    git clone https://github.com/Tiehuis/libhcs.git
    cmake .
    make
    sudo make install # Will install to /usr/local by default

To uninstall all installed files, one can run the following command:

    sudo xargs rm < install_manifest.txt

## Examples

A trivial example demonstrating the API is as follows. See ``examples``
for more in-depth examples.

```c
#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything

int main(void)
{
    // initialize data structures
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();

    // Generate a key pair with modulus of size 2048 bits
    pcs_generate_key_pair(pk, vk, hr, 2048);

    // libhcs works directly with gmp mpz_t types, so initialize some
    mpz_t a, b, c;
    mpz_inits(a, b, c, NULL);

    mpz_set_ui(a, 50);
    mpz_set_ui(b, 76);

    pcs_encrypt(pk, hr, a, a);  // Encrypt a (= 50) and store back into a
    pcs_encrypt(pk, hr, b, b);  // Encrypt b (= 76) and store back into b
    gmp_printf("a = %Zd\nb = %Zd\n", a, b); // can use all gmp functions still

    pcs_ee_add(pk, c, a, b);    // Add encrypted a and b values together into c
    pcs_decrypt(vk, c, c);      // Decrypt c back into c using private key
    gmp_printf("%Zd\n", c);     // output: c = 126

    // Cleanup all data
    mpz_clears(a, b, c, NULL);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);

    return 0;
}
```

To run this example, we need only need to link against libhcs and libgmp:

    clang -o example example.c -lhcs -lgmp
    ./example

## Overview (Comments)

### Repository contents

Documentation can be generated using doxygen. The config file is found in
``doc``. One can also read the header files found in ``include`` if doxygen is
not installed on the system.

Some benchmarks can be found in ``bench``. Currently, these test OpenMP support
and do not do much else. In the future, these could be used to conditionally
compile on certain systems, depending on the performance.

Header files and implementations are split between ``include`` and ``src``.
``src/com`` stores all impelementation common to all cryptoschemes.
Platform-specific code should be place here, also.

Some unit tests can be found in ``test``. Each file here should be a
self-contained file with its own main routine. These are compiled and can be
run after building with the command:

    make test

### Implementation details

The Paillier and Damgard-Jurik implementations are derived from
*A Generalization of Paillier's Public-Key System with Applications to
Electronic Voting, Damgard, Jurik, Nielsen*.

Large safe prime generation is a current problem. It can be extremely slow
for larger bits due to its random nature. Some algorithms have been proposed
(see *Efficient Generation of Prime Numbers, Joye, Paillier*). This has been
partially implemented over the naive scheme. Further reading regarding
possible attacks on these algorithms should also be considered (see
*On the Implementation of a Fast Prime Generation Algorithm, Clavier, Coron*).

### Future work (Improvements)

* Getting this to work on other systems i.e. Windows would be useful. The main
wall in this is getting GMP working first. CMake should make the rest simple,
and the only platform-specific code (random state seeding) is mostly in place
already.
* Ensuring the code is cryptographically secure against attacks.
* Further work done on other schemes. i.e (El-Gamal, Goldwasser-Micali)
* More unit tests written to ensure the schemes themselves are correct
* Profiling to determine particular performance improvements
* More examples written which exemplify how to use libhcs
* A command line tool which interfaces against this library would be invaluable
in providing quick prototyping and proof of concept of ideas utilizing libhcs.
