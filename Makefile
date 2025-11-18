# Simple Makefile for QRNG CLI project

PROJECT_NAME := qrng_cli
BIN_DIR := bin
SRC_DIR := src
TEST_DIR := tests

CC := gcc
CSTD := -std=c11
WARN := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
OPT := -O2
CFLAGS := $(CSTD) $(WARN) $(OPT)
LDFLAGS := 

TARGET := $(BIN_DIR)/qrng_encryptor
TEST_BIN := $(BIN_DIR)/tests

SRCS := $(SRC_DIR)/main.c \
        $(SRC_DIR)/input.c \
        $(SRC_DIR)/fileops.c \
        $(SRC_DIR)/crypto.c \
        $(SRC_DIR)/qrng.c \
        $(SRC_DIR)/util.c

OBJS := $(SRCS:.c=.o)

TEST_SRCS := $(TEST_DIR)/test_runner.c \
             $(TEST_DIR)/test_crypto.c \
             $(TEST_DIR)/test_fileops.c \
             $(TEST_DIR)/test_input.c \
             $(TEST_DIR)/test_integration.c \
             $(SRC_DIR)/fileops.c \
             $(SRC_DIR)/crypto.c \
             $(SRC_DIR)/qrng.c \
             $(SRC_DIR)/util.c

TEST_OBJS := $(TEST_SRCS:.c=.o)

.PHONY: all clean run test dirs

all: dirs $(TARGET)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

dirs: $(BIN_DIR)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(TEST_BIN): $(TEST_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(LDFLAGS)

run: $(TARGET)
	$(TARGET)

test: $(TEST_BIN)
	QRNG_STUB=1 $(TEST_BIN)

clean:
	rm -f $(SRC_DIR)/*.o $(TEST_DIR)/*.o $(TARGET) $(TEST_BIN)

# Dependencies
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRC_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/input.h $(SRC_DIR)/fileops.h $(SRC_DIR)/crypto.h $(SRC_DIR)/qrng.h $(SRC_DIR)/util.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(SRC_DIR)/crypto.h $(SRC_DIR)/fileops.h $(SRC_DIR)/qrng.h $(SRC_DIR)/util.h
	$(CC) $(CFLAGS) -c -o $@ $<
