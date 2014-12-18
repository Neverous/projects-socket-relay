CFLAGS=-O3 --std=gnu11 -Wall -Werror -Isrc/ -DNDEBUG
LFLAGS=-levent
CC?=gcc
STRIP?=strip

all: socket-server socket-relay

%.o: %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

socket-server: src/socket-server.o src/protocol/sha2.o
	mkdir -p bin
	${CC} ${CFLAGS} ${LFLAGS} -o bin/socket-server $^
	${STRIP} bin/socket-server

socket-relay: src/socket-relay.o src/protocol/sha2.o
	mkdir -p bin
	${CC} ${CFLAGS} ${LFLAGS} -o bin/socket-relay $^
	${STRIP} bin/socket-relay

install: all
	install -m 0755 bin/socket-relay /usr/local/bin/
	install -m 0755 bin/socket-server /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/socket-relay
	rm -f /usr/local/bin/socket-server

clean:
	rm -f *.o */*.o */*/*.o bin/*
