# Home Cloud server - édition lite (Termux, sans root)
CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -fstack-protector-strong
LDLIBS   = -lcrypto
# bionic (Android) intègre pthread dans libc ; ailleurs on le demande explicitement
ifneq ($(shell uname -o 2>/dev/null),Android)
LDLIBS  += -lpthread
endif
SRC      = $(wildcard src/*.c)
BIN      = homecloud-server
PREFIX  ?= /usr/local

all: $(BIN)
$(BIN): $(SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)
install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
clean:
	rm -f $(BIN)
.PHONY: all install clean
