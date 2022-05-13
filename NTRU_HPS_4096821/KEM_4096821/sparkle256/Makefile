# OPTION-1 PURE BUILD, no library (only sparkle and encryption files required)
release:
	gcc -I. main.c sparkle_ref.c

# OPTION- 2 BUILD by creating static library first
release-lib: lib
	gcc -I. mainc -L. -lsparkle256

lib:
	gcc -c sparkle_ref.c  -o sparkle_ref.o
	gcc -c encrypt.c  -o encrypt.o
	ar rcs libsparkle256.a sparkle_ref.o encrypt.o

clean : 
	@rm -f *.o
	@rm -f *.a
	@rm -f *.out