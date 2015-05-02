CC 	   ?= clang
CFLAGS += -g -Wall -Wextra
SRCS   := pcs.c pcs_t.c djcs.c djcs_t.c egcs.c hcs_rand.c com/*.c

all: hcs

hcs:
	$(CC) $(CFLAGS) -fPIC -shared -o ../lib/libhcs.so $(SRCS) -lgmp
