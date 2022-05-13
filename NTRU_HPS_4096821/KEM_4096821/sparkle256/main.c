// #include "sparkle_ref.h"

// int main(int argc, char const *argv[]) {
//   test_sparkle_ref(4, 10);
//   return 0;
// }
#include <stdio.h>

#include "api.h"
#include "encrypt.c"
#define SPARKLE_MAX_SIZE CRYPTO_KEYBYTES

static void log8(char *text, uint8_t *data, size_t len);

int main(int argc, char const *argv[]) {
  SparkleState state = {{1}, {1}};
  const uint8_t key[CRYPTO_KEYBYTES] = {1};
  const uint8_t nonce[CRYPTO_KEYBYTES] = {1};
  Initialize(&state, key, nonce);
  uint8_t *dec = (uint8_t *)"Prueba";
  uint8_t enc[SPARKLE_MAX_SIZE];
  ProcessPlainText(&state, enc, dec, SPARKLE_MAX_SIZE);
  log8("enc:", enc, SPARKLE_MAX_SIZE);
  ProcessCipherText(&state, enc, dec, SPARKLE_MAX_SIZE);
  printf("dec: %s\n", dec);
  return 0;
}

void log8(char *text, uint8_t *data, size_t len) {
  // size_t LIMIT = len;
  size_t LIMIT = len < 32 ? len : 32;
  printf("%s", text);
  for (size_t r = 0; r < LIMIT; r++) printf("%02x", *data++);
  if (len > LIMIT) printf("...%zu bytes", len);
  printf("\n");
}
