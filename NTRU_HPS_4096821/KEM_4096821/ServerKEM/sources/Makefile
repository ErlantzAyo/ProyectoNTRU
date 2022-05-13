TARGET = $(BIN_DIR)/ServerKEM


BIN_DIR = ../bin
INC_DIR = ../includes -I ../../sparkle256
SRC_DIR = .
OBJ_DIR = ../objects

SOURCES = $(foreach d,$(SRC_DIR),$(wildcard $(addprefix $(d)/*, .c )))

OBJS	=$(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(basename $(SOURCES))))

CFLAGS = -Wall -I$(INC_DIR)

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
	
	
