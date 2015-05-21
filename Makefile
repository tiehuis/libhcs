DIR_INC := /usr/local/include
DIR_LIB := /usr/local/lib

all: local

local:
	@(cd src && make)
	@mkdir -p test
	@(cd test && make)

install:
	cp lib/libhcs.so $(DIR_LIB)
	mkdir -p "$(DIR_INC)/libhcs/"
	cp src/*.h "$(DIR_INC)/libhcs/"
	@rm -f "$(DIR_INC)/libhcs/libhcs.h"
	cp src/libhcs.h "$(DIR_INC)"

uninstall:
	rm -f "$(DIR_LIB)/libhcs.so"
	rm -f $(DIR_INC)/libhcs/*.h
	rmdir "$(DIR_INC)/libhcs/"
	rm -f "$(DIR_INC)/libhcs.h"

doc:
	@(cd doc && make)

.PHONY: src doc
