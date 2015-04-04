CC 	   ?= clang
CFLAGS += -g -Wall -Wextra
SRCS   := pcs.c djcs.c egcs.c

all: hcs

hcs:
	$(CC) $(CFLAGS) -fPIC -shared -o ../lib/libhcs.so $(SRCS) com/*.c -lgmp
