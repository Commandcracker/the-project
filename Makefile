#!make

ifeq ($(OS), Windows_NT)
	CRAFTOS := craftos-pc
else
	CRAFTOS := craftos
endif

.PHONY: run
run:
	$(CRAFTOS) --id 42 --mount-ro /=./src
