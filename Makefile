CC = gcc
CFLAGS = -Wall -g -fPIC
LDFLAGS = -shared

all: rijndael.dll main.exe

rijndael.o: rijndael.c rijndael.h
	$(CC) $(CFLAGS) -c rijndael.c

rijndael.dll: rijndael.o
	$(CC) $(LDFLAGS) -o rijndael.dll rijndael.o

main.o: main.c rijndael.h
	$(CC) $(CFLAGS) -c main.c

main.exe: main.o rijndael.o
	$(CC) -o main.exe main.o rijndael.o

clean:
	del /Q *.o *.so *.dll main.exe 2>nul