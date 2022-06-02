CFLAGS=-O3 -Wall

# OPTION-1 PURE BUILD, no library (only sparkle and encryption files required)
release:
	$(CC) $(CFLAGS)  -I. main.c sparkle.c sparkle_ref.c

# OPTION- 2 BUILD by creating static library first
release-lib: lib
	$(CC) $(CFLAGS)  -I. main.c -L. -lsparkle256

lib:
	$(CC) $(CFLAGS)  -c sparkle_ref.c  -o sparkle_ref.o
	$(CC) $(CFLAGS)  -c encrypt.c  -o encrypt.o
	$(CC) $(CFLAGS)  -c sparkle.c  -o sparkle.o
	$(AR) rcs libsparkle256.a sparkle_ref.o encrypt.o sparkle.o

clean : 
	$(RM) -f *.o
	$(RM) -f *.a
	$(RM) -f *.out
