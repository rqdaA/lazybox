CC = gcc
CFLAGS = -Os -fno-builtin -nostdlib -nostartfiles -masm=intel
TARGET = tinybox
SOURCE = main.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)
	strip $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all
