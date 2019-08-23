CFLAGS = -g -Wall -O2
CFLAGS += -I../libhpack
CFLAGS += -I../libwuya

all: libhttp2.a

libhttp2.a: http2.o
	ar rcs $@ $^

clean:
	rm -f *.o libhttp2.a
