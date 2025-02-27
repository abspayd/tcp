CC = gcc
CFLAGS = -std=c99 -I. -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -g
TARGET = tcp

ODIR = obj

_OBJ = tcp.o tun.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

tcp: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $<

$(ODIR)/%.o: %.c %.h
	$(CC) $(CFLAGS) -c $@ $<

.PHONY: clean
clean:
	rm -f $(ODIR)/*.o
