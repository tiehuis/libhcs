CC	    ?= clang
CFLAGS  += -g -Wall -Wextra -I../src/ -L../lib/ -Wl,-rpath=../lib/ -std=c99
LDFLAGS += -lgmp -lhcs

all: voting sanity threshold

voting: voting.c
	$(CC) $(CFLAGS) voting.c $(LDFLAGS) -o voting

threshold: test_threshold.c
	$(CC) $(CFLAGS) test_threshold.c $(LDFLAGS) -o test_threshold

base: test_basesize_g.c
	$(CC) $(CFLAGS) test_basesize_g.c com/*.c $(LDFLAGS) -o test_base

negative: test_negative.c
	$(CC) $(CFLAGS) test_negative.c com/*.c $(LDFLAGS) -o test_negative

sanity: test_sanity.c
	$(CC) $(CFLAGS) test_sanity.c com/*.c $(LDFLAGS) -o test_sanity

test: test.c
	$(CC) $(CFLAGS) test.c com/*.c $(LDFLAGS) -o test
