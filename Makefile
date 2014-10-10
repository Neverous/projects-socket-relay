CFLAGS=-Os --std=gnu11 -flto -Wall -Werror -Isrc/
all: socket-server socket-relay

%.o: %.c %.h
	gcc ${CFLAGS} -o $@ -c $<

socket-server: src/log/log.o src/server/server.o src/protocol/message.o src/misc/sha2.o src/protocol/auth.o src/misc/bufferedSocket.o src/misc/cyclicBuffer.o src/server-main.c
	mkdir -p bin
	gcc ${CFLAGS} -o bin/socket-server $^

socket-relay: src/log/log.o src/relay/relay.o src/protocol/message.o src/misc/sha2.o src/protocol/auth.o src/misc/bufferedSocket.o src/misc/cyclicBuffer.o src/relay-main.c
	mkdir -p bin
	gcc ${CFLAGS} -o bin/socket-relay $^

clean:
	rm -f *.o */*/*.o bin/*
