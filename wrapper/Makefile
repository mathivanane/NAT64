CC = gcc
CFLAGS = -Wall -O0 -g
LDFLAGS = -L/usr/lib -lpcap
INCLUDE = -Ilib

all: wrapper.o process.o translate_ip.o connections.o checksum.o if.o storage.o lib/jsw_rbtree.o
	$(CC) $(CFLAGS) $(LDFLAGS) *.o lib/*.o	-o wrapper

wrapper.o: wrapper.c wrapper.h
	$(CC) $(CFLAGS) $(INCLUDE) -c wrapper.c		-o wrapper.o

process.o: process.c wrapper.h translate_ip.h
	$(CC) $(CFLAGS) $(INCLUDE) -c process.c		-o process.o

translate_ip.o: translate_ip.c translate_ip.h wrapper.h
	$(CC) $(CFLAGS) -c translate_ip.c		-o translate_ip.o

connections.o: connections.c wrapper.h
	$(CC) $(CFLAGS) -c connections.c		-o connections.o

checksum.o: checksum.c
	$(CC) $(CFLAGS) -c checksum.c			-o checksum.o

if.o: if.c wrapper.h
	$(CC) $(CFLAGS) -c if.c			-o if.o

storage.o: storage.c storage.h
	$(CC) $(CFLAGS) $(INCLUDE) -c storage.c		-o storage.o

# libraries
lib/jsw_rbtree.o: lib/jsw_rbtree.c lib/jsw_rbtree.h
	$(CC) $(CFLAGS) -c lib/jsw_rbtree.c		-o lib/jsw_rbtree.o

clean:
	rm -f wrapper *.o lib/*.o
