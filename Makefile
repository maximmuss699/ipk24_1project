CC=gcc
CFLAGS=-I. -Wall -Wextra -pedantic -std=c99 -g

all: ipk24chat-client

ipk24chat-client: IPK24-CHAT.c
	$(CC) -o ipk24chat-client IPK24-CHAT.c $(CFLAGS)

.PHONY: clean
clean:
	rm -f ipk24chat-client
