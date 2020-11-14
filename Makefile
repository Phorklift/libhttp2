CFLAGS = -g -Wall -Werror -O2
CFLAGS += -I../

all: libhttp2.a

libhttp2.a: http2.o http2_process.o http2_priority.o
	make -C libhpack
	ar rcs $@ $^ libhpack/*.o

clean:
	make -C libhpack clean
	rm -f *.o libhttp2.a
