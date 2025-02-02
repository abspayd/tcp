CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Waddress
BIN = main

.PHONY: all
all: main

main: main.c
	$(CC) $(CFLAGS) -o $@ $<


.PHONY: clean
clean:
	rm -f $(BIN)
