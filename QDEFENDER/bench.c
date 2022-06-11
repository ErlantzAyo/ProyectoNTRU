#include <stdio.h>
#include <sys/time.h>

#include "qdefender.h"

#define BENCH_MAX 1000

long currentTimeMillis() {
  struct timeval time;
  gettimeofday(&time, NULL);
  return time.tv_sec * 1000 + time.tv_usec / 1000;
}

static void warmCPU() {
  printf("Warming up CPU...\n");
  uint8_t arr[1000000];
  memset(arr, '.', sizeof(arr));
  for (size_t i = 0; i < 100000; i++) {
    for (size_t r = 0; r < sizeof(arr) - 2; r++) arr[r] = 3 + arr[r];
  };
  printf("Warming done (%u).\n", arr[55]);
}

int test_KEM(const char* name) {
  int status = 0;
  uint64_t t1, t2;
  printf("\n----- %s -----\n", name);
  KEM kem = KEM_create(name);
  OQS_KEM* kem_algorithm = get_kem_algorithm(name);
  int BENCH_MAX_KEYGEN = BENCH_MAX / 10;

  // keygen
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX_KEYGEN; r++) {
    if (KEM_generate_keys(&kem) != 0) return 1;
  }
  t2 = currentTimeMillis();
  printf("KEYGEN: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX_KEYGEN);

  // encaps
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX; r++) {
    if (KEM_encapsulate(&kem) != 0) return 1;
  }
  t2 = currentTimeMillis();
  printf("ENCAPS: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX);

  // decaps
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX; r++) {
    if (KEM_decapsulate(&kem) != 0) return 1;
  }
  t2 = currentTimeMillis();
  printf("DECAPS: %lf ms/op\n\n", (t2 - t1) * 1.0 / BENCH_MAX);

  // Destroy all
  KEM_destroy(&kem);
  return 0;
}

int main(int argc, const char* argv[]) {
  if (argc <= 1) {
    printf("Usage: ./bench alg1 alg2 (see kem.h for names)...\n");
    printf("Example: ./bench Kyber768 ...\n");
    return 0;
  }

  warmCPU();
  for (size_t r = 1; r < argc; r++) {
    const char* name = argv[r];
    if (test_KEM(name) != 0) printf("@@@@ INVALID %s BENCH@@@ \n", name);
  }
  return 0;
}