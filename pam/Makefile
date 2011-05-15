include $(GOROOT)/src/Make.inc
TARG=pam
GOFILES:=pamdefs.go
CGOFILES:=pam.go
CGO_LDFLAGS:=-lpam
CGO_OFILES:=gopam.o

include $(GOROOT)/src/Make.pkg

DOLLAR:="$"

pamdefs.go: pamdefs.c
	godefs `echo -n $(CGO_FLAGS) | sed 's/\(^ ^$(DOLLAR)]*\)/-f \1/g'` -g pam pamdefs.c > pamdefs.go
	gofmt -w pamdefs.go


