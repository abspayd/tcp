INCLUDE_DIR := include
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
TEST_BUILD_DIR := $(BUILD_DIR)/tests
TEST_DIR := tests

CC := gcc
CFLAGS_DEBUG := -std=c99 -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -MMD -MP -lmd -g
CFLAGS_RELEASE := -std=c99 -O2 -Wall -Wextra -Wpedantic -Wpadded -MMD -MP -lmd
INCLUDES := -I$(INCLUDE_DIR)

SRCS := $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/util/*.c $(SRC_DIR)/tcp/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:%.o=%.d)

MAIN_OBJ := $(BUILD_DIR)/main.o
SERVER_OBJ := $(BUILD_DIR)/server.o
CLIENT_OBJ := $(BUILD_DIR)/client.o

LIB_SRCS := $(filter-out $(SRC_DIR)/main.c $(SRC_DIR)/server.c $(SRC_DIR)/client.c,$(SRCS))
LIB_OBJS := $(LIB_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
LIB_TARGET := $(BUILD_DIR)/libtcp.a

TEST_INCLUDES := -I$(INCLUDE_DIR) -I$(TEST_DIR)
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS := $(TEST_SRCS:$(TEST_DIR)/%.c=$(TEST_BUILD_DIR)/%.o)
TEST_DEPS := $(TEST_OBJS:%.o=%.d)

TEST_TARGET := $(BIN_DIR)/test_runner
TEST_CFLAGS := -std=c99 -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -MMD -MP -L$(BUILD_DIR) -lmd -ltcp -g

MODE ?= DEBUG
MODE_UPPER := $(shell echo $(MODE) | tr '[:lower:]' '[:upper:]')

ifeq ($(MODE_UPPER), DEBUG)
    CFLAGS := $(CFLAGS_DEBUG)
else ifeq ($(MODE_UPPER), RELEASE)
    CFLAGS := $(CFLAGS_RELEASE)
else
    $(error Unsupported build mode: "$(MODE)". Please use one of the supported modes: RELEASE or DEBUG)
endif

TARGET := $(BIN_DIR)/tcp
SERVER_TARGET := $(BIN_DIR)/server
CLIENT_TARGET := $(BIN_DIR)/client

.PHONY: all test clean

all: $(TARGET) $(SERVER_TARGET) $(CLIENT_TARGET)

$(BUILD_DIR)/$(LIB_TARGET):
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(MAIN_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

$(SERVER_TARGET): $(SERVER_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

$(CLIENT_TARGET): $(CLIENT_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(LIB_TARGET): $(LIB_OBJS)
	ar rcs $@ $^

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

test: $(TEST_TARGET)
	@./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJS) $(LIB_TARGET) | $(BIN_DIR)
	$(CC) $(TEST_CFLAGS) $(TEST_INCLUDES) -o $@ $^

$(TEST_BUILD_DIR)/%.o: $(TEST_DIR)/%.c | $(TEST_BUILD_DIR)
	$(CC) $(TEST_CFLAGS) $(TEST_INCLUDES) -c -o $@ $<

$(TEST_BUILD_DIR):
	mkdir -p $@

ifeq (,$(filter clean,$(MAKECMDGOALS)))
    -include $(DEPS)
    ifeq ($(filter test,$(MAKECMDGOALS)),test)
        -include $(TEST_DEPS)
    endif
endif

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
