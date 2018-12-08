CC=gcc
CFLAGS:= -O3 -Wpedantic -g

SRC:=src
LIB:=-I -lcrypto

MAIN_DGK:=src/main.c

DGK_OBJS:=key_generation.o randombytes.o dgk.o

BUILD:=bin/build
BIN:=bin

folders:
	@echo -e "\n### Creating build folders\n"
	mkdir -p $(BUILD)

%.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(LIB) -o $(BUILD)/$@

dgk: $(DGK_OBJS) | folders
	@echo -e "\n### Compiling the comparison\n"
	$(CC) $(CFLAGS) $(MAIN_DGK) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@ -lgmp

clean:
	rm -f vgcore.*
	rm -rf ./bin
