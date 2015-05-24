CC 	   ?= clang
CFLAGS += -O2 -Wall -Wextra -std=c99
SRCS   := pcs.c pcs_t.c djcs.c djcs_t.c egcs.c hcs_rand.c com/*.c

all: hcs

hcs: $(SRCS)
	@(mkdir -p ../lib)
	$(CC) $(CFLAGS) -fPIC -shared -o ../lib/libhcs.so $(SRCS) -lgmp
