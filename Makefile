IDIR = include
SRCDIR = src
ODIR = obj

CC = gcc
CFLAGS = -std=c99 -I$(IDIR) -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -g
TARGET = tcp

SRC = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst %.c,$(ODIR)/%.o,$(notdir $(SRC)))
DEPS = $(wildcard $(IDIR)/*.h)

.PHONY: all
all: $(TARGET)

$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS) | $(ODIR)
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

