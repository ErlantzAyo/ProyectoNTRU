

#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
/*Benchmark*/
#include <time.h>
#include "file_io.h"

#include "utils.h"

void getTempMsg (uint8_t* msg){
  double dato = 0;
  dato = readFileDouble("/sys/class/thermal/thermal_zone0/temp");
  dato = dato/1000;
  sprintf((char*)msg,"Temp = %.2fº",dato);
}

void printBstr(const char *S, const uint8_t *key, size_t L) {
  size_t i;
    OUTPUT(("%s", S));
  for (i = 0; i < L; i++) {
    OUTPUT(("%02X", key[i]));
  }
  if (L == 0) {
  OUTPUT(("%02X", key[i]));
  }
    OUTPUT(("\n\n"));
}

double TiempoProceso(clock_t tic, clock_t toc) {
  double elapsed = (double)(toc - tic) * 1000.0 / CLOCKS_PER_SEC;

  return elapsed;
}

void log8(char *text, uint8_t *data, size_t len) {
  size_t LIMIT = len < 32 ? len : 32;
  OUTPUT(("%s", text));
  
  for (size_t r = 0; r < LIMIT; r++)OUTPUT(("%02x", *data++));
  if (len > LIMIT)OUTPUT(("...%zu bytes", len));
  OUTPUT(("\n"));
}
