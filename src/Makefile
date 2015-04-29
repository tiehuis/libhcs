CC 	   ?= clang
CFLAGS += -g -Wall -Wextra
SRCS   := pcs.c djcs.c egcs.c pcs2.c pcs_t.c hcs_rand.c

all: hcs

hcs:
	$(CC) $(CFLAGS) -fPIC -shared -o ../lib/libhcs.so $(SRCS) com/*.c -lgmp
