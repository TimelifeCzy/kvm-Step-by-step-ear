BIN := kernel.bin
ELF := kernel.elf
OBJ := kernel.o

all: $(BIN)
$(BIN): $(ELF)
	objcopy -O binary $< $@

$(ELF): $(OBJ)
	$(LD) -Ttext=0x00 -nostdlib -static $< -o $@

%.o: %.S
	$(CC) -nostdlib -c $< -o $@

clean:
	rm -rf $(OBJ) $(BIN) $(ELF)
