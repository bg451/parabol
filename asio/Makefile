CC=gcc
CCFLAGS=-Wall -Werror -ggdb #-pg

all: asio.o $(KEPOLLOBJ)
asio.o: asio.c asio.h $(KEPOLLHDR)
	$(CC) $(CCFLAGS) $(KEPOLLDEF) -c asio.c
Kepoll.o: Kepoll.s asio.h Kepoll.h
	$(CC) $(CCFLAGS) -c Kepoll.s
