CC	    ?= clang
CFLAGS  += -g -Wall -Wextra -I../src/ -L../lib/ -Wl,-rpath=../lib/ -std=c99
LDFLAGS += -lgmp -lhcs

all: std_voting sanity threshold dj_threshold

thresh_voting: test_thresh_voting.c
	$(CC) $(CFLAGS) test_thresh_voting.c $(LDFLAGS) -o test_thresh_voting

std_voting: test_std_voting.c
	$(CC) $(CFLAGS) test_std_voting.c $(LDFLAGS) -o test_std_voting

threshold: test_threshold.c
	$(CC) $(CFLAGS) test_threshold.c $(LDFLAGS) -o test_threshold

dj_threshold: test_dj_threshold.c
	$(CC) $(CFLAGS) test_dj_threshold.c $(LDFLAGS) -o test_dj_threshold

base: test_basesize_g.c
	$(CC) $(CFLAGS) test_basesize_g.c com/*.c $(LDFLAGS) -o test_base

negative: test_negative.c
	$(CC) $(CFLAGS) test_negative.c com/*.c $(LDFLAGS) -o test_negative

sanity: test_sanity.c
	$(CC) $(CFLAGS) test_sanity.c com/*.c $(LDFLAGS) -o test_sanity

lib:
	(cd ../src && make)

clean:
	rm -rf test_std_voting test_sanity test_threshold

.PHONY: clean lib
