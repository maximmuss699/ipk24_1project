CC=gcc
CFLAGS=-I. -Wall -Wextra -pedantic -std=c99 -g

all: IPK24-CHAT

IPK24-CHAT: IPK24-CHAT.c
	$(CC) -o IPK24-CHAT IPK24-CHAT.c $(CFLAGS)

.PHONY: clean
clean:
	rm -f IPK24-CHAT
