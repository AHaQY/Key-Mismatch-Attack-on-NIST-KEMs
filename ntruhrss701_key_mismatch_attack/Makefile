CC=/usr/bin/gcc
LDFLAGS=-lcrypto

SOURCES = fips202.c kem.c owcpa.c pack3.c packq.c poly.c sample.c verify.c rng.c hrss.c
HEADERS = api.h fips202.h kem.h poly.h owcpa.h params.h sample.h verify.h rng.h

hrss: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm hrss

