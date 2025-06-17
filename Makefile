# Determine the operating system
UNAME := $(shell uname)

# Default compiler settings
CC = gcc

# Change compiler based on OS
ifeq ($(UNAME), Darwin)
    CC = clang
endif

ifeq ($(UNAME), FreeBSD)
    CC = clang
endif

# compiler flags:
#  -std=c2x	comply with C23
#  -O3		optimize level at 3
#  -g		adds debugging information to the executable file
#  -Wall	turns on most, but not all, compiler warnings
#  -Wextra	additional warnings not covered by -Wall
CFLAGS = -std=c2x -O3 -Wall -Wextra -I.
RM = rm -f


# the build target executable:
TARGET = tcp_probe_parser
default: $(TARGET)

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

.PHONY: depend clean

clean:
	$(RM) $(TARGET)
