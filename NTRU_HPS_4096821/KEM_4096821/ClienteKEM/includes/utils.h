
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
/*Benchmark*/
#include <time.h>


void printBstr(const char *, const uint8_t *, size_t);
 void log8(char *text, uint8_t *data, size_t len);
double TiempoProceso(clock_t, clock_t);
