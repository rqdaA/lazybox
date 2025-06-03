CC = gcc
CFLAGS = -fno-builtin -masm=intel -nostdlib -nostartfiles -O3 -fno-stack-protector
LDFLAGS = -T custom.ld -static -s
TARGET = lazybox
SOURCE = main.c

all: $(TARGET) lazybox.c

$(TARGET): $(SOURCE)
	$(CC) $(LDFLAGS) $(CFLAGS) $(SOURCE) -o $(TARGET)

lazybox.c: $(TARGET)
	python -c 'open("lazybox.c", "w").write("char lazybox[] = \"" + "".join(f"\\x{e:02x}" for e in open("lazybox", "rb").read()) + "\";\n")'

clean:
	rm -f $(TARGET) lazybox.c

.PHONY: all clean
