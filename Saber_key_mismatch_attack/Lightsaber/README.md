#To compile on Ubuntu:

sudo apt-get install make gcc libssl-dev
make

#To compile on Mac OS X using brew:

brew install openssl
make OPENSSL_DIR=/usr/local/opt/openssl

#Running:
```sh
$ ./test/test_kem
```
#Additional instructions

- `kem.c`: saberpke modified from saberkem
- `test/test_kem.c`: main function on launching key mismatch attack
  