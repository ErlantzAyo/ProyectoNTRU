

#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
/*Benchmark*/
#include <time.h>

#include "utils.h"


void printBstr(const char *S, const uint8_t *key, size_t L) {
  size_t i;
  printf("%s", S);
  for (i = 0; i < L; i++) {
    printf("%02X", key[i]);
  }
  if (L == 0) {
    printf("00");
  }
  printf("\n\n");
}

double TiempoProceso(clock_t tic, clock_t toc) {
  double elapsed = (double)(toc - tic) * 1000.0 / CLOCKS_PER_SEC;

  return elapsed;
}

void log8(char *text, uint8_t *data, size_t len) {
  // size_t LIMIT = len;
  size_t LIMIT = len < 32 ? len : 32;
  printf("%s", text);
  for (size_t r = 0; r < LIMIT; r++) printf("%02x", *data++);
  if (len > LIMIT) printf("...%zu bytes", len);
  printf("\n");
}
