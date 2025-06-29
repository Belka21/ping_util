CC = g++
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -lpcap
SRC_DIR = src
OBJ_DIR = obj

SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))

all: pingmac

pingmac: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) pingmac

install: pingmac
	cp pingmac /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/pingmac

.PHONY: all clean install uninstall
