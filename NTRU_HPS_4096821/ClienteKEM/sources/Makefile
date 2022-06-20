
TARGET = $(BIN_DIR)/ClientKEM

BIN_DIR = ../bin
INC_DIR = ../includes -I ../../sparkle256
SRC_DIR = .
OBJ_DIR = ../objects

SOURCES = $(foreach d,$(SRC_DIR),$(wildcard $(addprefix $(d)/*, .c )))

OBJS = $(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(basename $(SOURCES))))

# macros to compile in default(benchmarks) or production(continuous) modes
# MACROS = -DPRODUCTION
# MACROS = -DBENCH
MACROS =

CFLAGS =-O3 -Wall $(MACROS) -I$(INC_DIR)

$(TARGET) : $(OBJS)
	mkdir -p $(BIN_DIR)
	gcc $(CFLAGS) $(OBJS) -o $(TARGET)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	mkdir -p $(OBJ_DIR)
	gcc -c -MD $(CFLAGS) $< -o $@
-include $(OBJ_DIR)/*.d

.PHONY: clean
clean :
	@rm  -r $(OBJ_DIR) $(BIN_DIR)
	@rm -f *.o


#--------------BENCHMARKS-----------------
OBJS2=$(subst ../objects/./client.o,,$(OBJS))
benchmark:
  # usage: make benchmark && time ../bin/benchmark 127.0.0.1 8080
	$(CC) $(CFLAGS) $@s/$@.c $(OBJS2) -o $(BIN_DIR)/$@
