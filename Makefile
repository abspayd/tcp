CC = gcc
CFLAGS = -std=c99 -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -Werror -g
TARGET = main

.PHONY: all
all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $<

client: client.c
	$(CC) $(CFLAGS) -o $@ $<

server: server.c
	$(CC) $(CFLAGS) -o $@ $<

tun: tun.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f main server client tun
