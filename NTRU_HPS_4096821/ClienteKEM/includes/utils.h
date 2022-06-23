
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
/*Benchmark*/
#include <time.h>

#ifdef BENCH
  #define OUTPUT(x)
#else
  #define OUTPUT(x) printf x
#endif

void getTempMsg (uint8_t*);
void printBstr(const char *, const uint8_t *, size_t);
 void log8(char *text, uint8_t *data, size_t len);
double TiempoProceso(clock_t, clock_t);
