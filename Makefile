# Compiler
CC      := gcc

# Keep the assignment's standard
CFLAGS  := -Wall -Werror -ansi

# Target executable
TARGET  := build/main.out

# Sources (flat layout: next to Makefile)
SRCS    := main.c mfa_util.c mfa.c linked_list.c

# Objects go in build/
OBJS    := $(SRCS:%.c=build/%.o)

# Libraries
LDLIBS  := -lm

# Default
all: $(TARGET)

# Link: ensure build/ exists and link objects
$(TARGET): $(OBJS) | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJS) $(LDLIBS)

# Compile: from current dir to build/
build/%.o: %.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Ensure build/ exists
build:
	mkdir -p $@

.PHONY: clean run
clean:
	$(RM) -r build
run: $(TARGET)
	./$(TARGET)
