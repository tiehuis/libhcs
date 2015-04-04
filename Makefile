all: src doc

src: src/*
	@(cd src && make)

doc: src/*
	$(shell doxygen .doxycfg)
