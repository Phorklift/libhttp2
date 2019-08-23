CFLAGS = -g -Wall -O2
CFLAGS += -I../
CFLAGS += -I../../libloop/
CFLAGS += -I../../libhpack/
CFLAGS += -I../../libwuya/
LDFLAGS += -L../
LDFLAGS += -L../../libloop/
LDFLAGS += -L../../libhpack/
LDFLAGS += -L../../libwuya/
LDLIBS = -lhttp2 -lloop -lwuya -lssl -lhpack -lcrypto


all: server

server: server.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f *.o server
