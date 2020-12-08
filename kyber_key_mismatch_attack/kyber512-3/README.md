This is key mismatch attack demo for Kyber512 NIST Round 3

# Structure

PQCgenKAT_kem.c: the entrance of attack, 

kem.c:  building the oracle 

indcpa.c: choosing attack parameters

test.p6: test queries  

time.p6: test  time

# Build and Run

To build it, you need to have openssl  and make on linux or Mac os.

> make

After making, then you can run 

>  ./PQCgenKAT_kem \<num\>

`<num>` is a integer used as a random seed. For example, `./PQCgenKAT_kem 1`

To run test, you need to install [rakudo](https://rakudo.org/) and run

> raku test.p6
>
> raku time.p6
>
> 