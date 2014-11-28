CFLAGS=-O3 --std=gnu11 -flto -Wall -Werror -Isrc/ -levent -DNDEBUG
all: socket-server socket-relay

%.o: %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

socket-server: src/socket-server.c src/protocol/sha2.c
	mkdir -p bin
	${CC} ${CFLAGS} -o bin/socket-server $^

socket-relay: src/socket-relay.c src/protocol/sha2.c
	mkdir -p bin
	${CC} ${CFLAGS} -o bin/socket-relay $^

clean:
	rm -f *.o */*.o */*/*.o bin/*
