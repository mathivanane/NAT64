CC = gcc
CFLAGS = -Wall -O0
LDFLAGS = -L/usr/lib -lpcap

all: wrapper.o process.o translate_ip.o connections.o checksum.o
	$(CC) $(CFLAGS) $(LDFLAGS) *.o	-o wrapper

wrapper.o: wrapper.c wrapper.h
	$(CC) $(CFLAGS) -c wrapper.c		-o wrapper.o

process.o: process.c wrapper.h translate_ip.h
	$(CC) $(CFLAGS) -c process.c		-o process.o

translate_ip.o: translate_ip.c translate_ip.h wrapper.h
	$(CC) $(CFLAGS) -c translate_ip.c		-o translate_ip.o

connections.o: connections.c wrapper.h
	$(CC) $(CFLAGS) -c connections.c		-o connections.o

checksum.o: checksum.c
	$(CC) $(CFLAGS) -c checksum.c		-o checksum.o

clean:
	rm -f wrapper *.o
