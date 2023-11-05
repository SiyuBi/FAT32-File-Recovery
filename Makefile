CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra -lcrypto

.PHONY: all
all: nyufile

nyufile: nyufile.o
	$(CC) $(CFLAGS) -o nyufile nyufile.o

nyufile.o: nyufile.c
	$(CC) $(CFLAGS) -c nyufile.c

.PHONY: clean
clean:
	rm -f *.o nyufile