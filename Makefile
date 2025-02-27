IDIR = include
CC = gcc
CFLAGS = -std=c99 -I$(IDIR) -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -g
TARGET = tcp

ODIR = obj
_OBJS = tcp.o tun.o
OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))

_DEPS = tcp.h tun.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

.PHONY: all
all: $(TARGET)

$(ODIR)/%.o: %.c $(DEPS) | $(ODIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJS): $(ODIR)
$(ODIR):
	mkdir $(ODIR)

.PHONY: tun tun-clean
tun:
	sudo ./scripts/add_tun.sh tun0
tun-clean:
	sudo ./scripts/del_tun.sh tun0

tcp: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(ODIR)/*.o tcp

