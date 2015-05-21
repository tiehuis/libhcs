all: src doc

src:
	@(cd src && make)

doc:
	@(cd doc && make)

.PHONY: src doc
