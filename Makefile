CFLAGS=-Os --std=gnu11 -flto -Wall -Werror -Isrc/ -levent
all: socket-server socket-relay

%.o: %.c %.h
	gcc ${CFLAGS} -o $@ -c $<

socket-server: src/socket-server.c
	mkdir -p bin
	gcc ${CFLAGS} -o bin/socket-server $^

socket-relay: src/socket-relay.c src/protocol/sha2.c
	mkdir -p bin
	gcc ${CFLAGS} -o bin/socket-relay $^

clean:
	rm -f *.o */*.o */*/*.o bin/*
