BINARY = codesign

OBJS = ldid.o sha1.o lookup2.o appbundle.o

CFLAGS = -Wall -Wextra -I. -g -Wno-deprecated-declarations
LDFLAGS = 
LIBS = -lplist

all: $(BINARY)

$(BINARY): $(OBJS)
	g++ $(LDFLAGS) -o $(BINARY) $(OBJS) $(LIBS)

%.o: %.c
	g++ -c -x c $(CFLAGS) $< -o $@

%.o: %.cpp
	g++ -c -x c++ $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(BINARY)
.PHONY: clean
