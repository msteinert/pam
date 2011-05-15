include $(GOROOT)/src/Make.inc

.PHONY: all pam install examples clean

all: install examples

pam:
	gomake -C pam

install: pam
	gomake -C pam install

examples:
	gomake -C examples

clean:
	gomake -C pam clean
	gomake -C examples clean


