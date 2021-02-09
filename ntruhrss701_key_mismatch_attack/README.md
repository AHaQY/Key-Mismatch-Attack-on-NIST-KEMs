#To compile on Ubuntu:

sudo apt-get install make gcc libssl-dev
make

#To compile on Mac OS X using brew:

brew install openssl
make OPENSSL_DIR=/usr/local/opt/openssl

#Running:
```sh
$ ./hrss
```
#Additional instructions

- `kem.c`: CPA version of NTRU-HRSS KEM
- `hrss.c`: main function on launching key mismatch attack on NTRU-HRSS KEM
  