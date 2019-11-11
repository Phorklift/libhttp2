CFLAGS = -g -Wall -O2
CFLAGS += -Ilibhpack -I../libwuya

all: libhttp2.a

libhttp2.a: http2.o
	make -C libhpack
	ar rcs $@ $^ libhpack/*.o

clean:
	make -C libhpack clean
	rm -f *.o libhttp2.a
