CC = g++
CFLAGS = -Wall -Wextra -O3 -mavx2
INCLUDES = -I../include -I..
SRCS = test_hash.cpp ../Hash/Hash.c ../Hash/sha256_avx2.c ../Hash/ripemd160_avx2.c

all: test_hash

test_hash: $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

clean:
	rm -f test_hash
