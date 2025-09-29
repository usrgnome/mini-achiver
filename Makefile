# Compiler
CC      := gcc

# Flags (warnings + strict ANSI mode unless you switch to -std=c11)
CFLAGS  := -Wall -Werror -ansi

# Include path
CPPFLAGS := -Iinclude

# Target executable
TARGET  := build/main.out

# Source files
SRCS    := src/main.c src/mfa_util.c src/mfa.c src/linked_list.c

# Object files (mirrors SRCS but inside build/)
OBJS    := $(SRCS:src/%.c=build/%.o)

# Libraries to link
LDLIBS  := -lm

# Default rule
all: $(TARGET)

# Link step
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJS) $(LDLIBS)

# Compile step: place .o files inside build/
build/%.o: src/%.c | build
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Ensure build/ directory exists
build:
	mkdir -p build

# Cleaning
.PHONY: clean run
clean:
	$(RM) -r build

# Run helper
run: $(TARGET)
	./$(TARGET)
