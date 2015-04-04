INC_PATH = ../../include
LIB_PATH = ../../lib

all:
	$(CC) -Wl,-rpath=$(LIB_PATH) -L$(LIB_PATH) -I$(INC_PATH) -g main.c -o tests -lpcs -lgmp
