bip38tool
=========

This tool generates bitcoin addresses and encrypts them using the BIP38 process. 


Requires
--------

- Go 1.2
- Git
- Mecruial (needed to to checkout go crypto libraries)


Build Instructions
------------------

1. checkout source into your $GOROOT/src/ directory and change directory into it.
2. run go get to download dependancies.
3. run go build


Examples
--------

    bip38tool encrypt -p 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS

    BIP38_PASS=secret bip38tool encrypt new

    cat keyfile | BIP38_PASS=secret bip38tool encrypt batch

The keyfile is a list of private keys one per line in hex or base58 format.

    BIP38_PASS=secret bip38tool decrypt 6PRQ7ivF6rFMn1wc7z6w1ZfFsKh4EAY1mhF3gCYkw8PLRMwfZNVqeqmW3F

Using OpenSSL for key generation
--------------------------------

While the tool will use a secure random generator, if you would like to use one that
was generated using a different tool that is an option.

If using openssl for the key generation generate a random seed to ensure it has
the highest quality entropy. (see: http://crypto.stackexchange.com/questions/9412/)

    dd if=/dev/random bs=1 count=1024 of=rndfile
    RANDFILE=rndfile openssl ecparam -genkey -name secp256k1 -outform DER | xxd -p -c 125 | cut -c 29-92
