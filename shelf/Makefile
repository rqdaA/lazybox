ASM = nasm
LD = ld
ASMFLAGS = -f elf64
TARGET = shelf
SOURCE = tiny.asm
OBJECT = shelf.o

all: $(TARGET)

$(OBJECT): $(SOURCE)
	$(ASM) $(ASMFLAGS) $(SOURCE) -o $(OBJECT)

$(TARGET): $(OBJECT)
	$(LD) $(OBJECT) -o $(TARGET)
	strip $(TARGET)

clean:
	rm -f $(OBJECT) $(TARGET)

.PHONY: all clean
