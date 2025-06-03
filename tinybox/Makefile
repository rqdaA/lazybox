CC = gcc
CFLAGS = -fno-builtin -masm=intel -nostdlib -nostartfiles -O3 -fno-stack-protector
LDFLAGS = -T custom.ld -static -s
TARGET = tinyelf
SOURCE = main.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(LDFLAGS) $(CFLAGS) $(SOURCE) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all
