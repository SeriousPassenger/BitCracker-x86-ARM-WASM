CC = g++
CFLAGS :=  -Wall -Wextra -O3 \
	-Wno-unused-variable -Wno-unused-but-set-variable -Wno-strict-aliasing \
	-Wno-deprecated-copy
LDFLAGS = -lstdc++ -lsecp256k1_cpu -lssl -lcrypto

INCLUDES = -I./include
LIBS = -L./lib

BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_DIR = $(BUILD_DIR)/obj
SRCS = Address.cpp main.cpp config.cpp
OBJS = $(SRCS:%.cpp=$(OBJ_DIR)/%.o)

all: main

main: $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(BIN_DIR)/main $(OBJS) $(LIBS) $(LDFLAGS)

$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(BUILD_DIR)

