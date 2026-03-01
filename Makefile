INCLUDE_DIR := include
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

SRCS := $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/util/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:%.o=%.d)

CC := gcc
CFLAGS_DEBUG := -std=c99 -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -MMD -MP -g
CFLAGS_RELEASE := -std=c99 -O2 -Wall -Wextra -Wpedantic -Wpadded -MMD -MP
INCLUDES := -I$(INCLUDE_DIR)

TEST_BUILD_DIR := build/tests
TEST_DIR := tests
TEST_INCLUDES := -I$(INCLUDE_DIR) -I$(TEST_DIR)
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS := $(TEST_SRCS:$(TEST_DIR)/%.c=$(TEST_BUILD_DIR)/%.o)
TEST_DEPS := $(TEST_OBJS:%.o=%.d)
TEST_TARGET := test_runner
TEST_CFLAGS := -std=c99 -fsanitize=address -Wall -Wextra -Wpedantic -Wpadded -MMD -MP -g

MODE ?= DEBUG
MODE_UPPER := $(shell echo $(MODE) | tr '[:lower:]' '[:upper:]')

ifeq ($(MODE_UPPER), DEBUG)
    CFLAGS := $(CFLAGS_DEBUG)
else ifeq ($(MODE_UPPER), RELEASE)
    CFLAGS := $(CFLAGS_RELEASE)
else
    $(error Unsupported build mode: "$(MODE)". Please use one of the supported modes: RELEASE or DEBUG)
endif

TARGET := tcp

.PHONY: all test clean

all: $(BIN_DIR)/$(TARGET)

$(BIN_DIR)/$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

test: $(BIN_DIR)/$(TEST_TARGET)
	@./$(BIN_DIR)/$(TEST_TARGET)

$(BIN_DIR)/$(TEST_TARGET): $(TEST_OBJS) | $(BIN_DIR)
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
