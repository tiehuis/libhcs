CC	    ?= clang
CFLAGS  += -g -Wall -Wextra -I../src/ -L../lib/ -Wl,-rpath=../lib/
LDFLAGS += -lgmp -lhcs

all: test_base test_negative voting

voting: voting.c
	$(CC) $(CFLAGS) voting.c $(LDFLAGS) -o voting

test_base: test_basesize_g.c
	$(CC) $(CFLAGS) test_basesize_g.c com/*.c $(LDFLAGS) -o test_base

test_negative: test_negative.c
	$(CC) $(CFLAGS) test_negative.c com/*.c $(LDFLAGS) -o test_negative

test:
	$(CC) $(CFLAGS) test.c $(LIBS)
