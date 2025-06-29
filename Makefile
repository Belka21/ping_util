CC = g++
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap

all: pingmac

pingmac: main.cpp
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f pingmac

install: pingmac
	cp pingmac /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/pingmac
