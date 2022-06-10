
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

.PHONY: cpu
cpu:
  # make cpu && time ../bin/benchmarkCPU
	cc -O3 -Wall  -I../includes -I ../../sparkle256 ./benchmarks/benchmarkCPU.c ../objects/./crypto_sort_int32.o ../objects/./poly_s3_inv.o ../objects/./poly_rq_mul.o ../objects/./poly_mod.o ../objects/./sample.o ../objects/./poly_r2_inv.o ../objects/./cmov.o ../objects/./packq.o ../objects/./poly.o ../objects/./randombytes.o ../objects/./poly_lift.o ../objects/./fips202.o ../objects/./file_io.o ../objects/./owcpa.o ../objects/./transform.o ../objects/./utils.o ../objects/./sample_iid.o ../objects/./kem.o ../objects/./sha2.o ../objects/./sparkle_ref.o ../objects/./aes.o ../objects/./pack3.o ../objects/./nistseedexpander.o ../objects/./sp800-185.o -o ../bin/benchmarkCPU
