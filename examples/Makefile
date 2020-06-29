CFLAGS = -g -Wall -O2
CFLAGS += -I../
CFLAGS += -I../../libloop/
CFLAGS += -I../../libwuya/
CFLAGS += -I../libhpack/
LDFLAGS += -L../
LDFLAGS += -L../../libloop/
LDFLAGS += -L../../libwuya/
LDFLAGS += -L../libhpack/
LDLIBS = -lhttp2 -lloop -lwuya -lssl -lhpack -lcrypto


all: server

server: server.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f *.o server
