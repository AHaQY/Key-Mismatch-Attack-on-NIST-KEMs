#To compile on Ubuntu:

sudo apt-get install make gcc libssl-dev
make

#To compile on Mac OS X using brew:

brew install openssl
make OPENSSL_DIR=/usr/local/opt/openssl

#Running:
```sh
$ ./frodo976/test_KEM
```
#Additional instructions

- `src/kem.c`: frodopke modified from frodokem
- `tests/test_kem.c`: main function on launching key mismatch attack
  