# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -fPIC
LDFLAGS = -shared

# Platform-specific settings
ifeq ($(OS),Windows_NT)
    TARGET_LIB = rijndael.dll
    RM = del /Q
else
    TARGET_LIB = rijndael.so
    RM = rm -f
endif

# Default target
all: $(TARGET_LIB) main.exe

# Object files
rijndael.o: rijndael.c rijndael.h
	$(CC) $(CFLAGS) -c rijndael.c

# Shared library
$(TARGET_LIB): rijndael.o
	$(CC) $(LDFLAGS) -o $(TARGET_LIB) rijndael.o

# Main program
main.o: main.c rijndael.h
	$(CC) $(CFLAGS) -c main.c

main.exe: main.o rijndael.o
	$(CC) -o main.exe main.o rijndael.o

# Clean up
clean:
	$(RM) *.o $(TARGET_LIB) main.exe