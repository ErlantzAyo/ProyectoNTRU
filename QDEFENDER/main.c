#include <stdio.h>

#include "qdefender.h"
int test_KEM(const char* name) {
  int status;

  // Create and init the KEM object
  KEM kem = KEM_create(name);
  OQS_KEM* kem_algorithm = get_kem_algorithm(name);

  // [OPTIONAL] Params for external apps
  // CRYPTO_PARAMS params;
  // status = KEM_init(name, &params);

  // [OPTIONAL] Generate private and public keys
  status = KEM_generate_keys(&kem);
  if (status != 0) {
    fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
    KEM_destroy(&kem);
    return status;
  }
  log8("pubKey: ", kem.public_key, kem_algorithm->length_public_key);
  log8("prvKey: ", kem.secret_key, kem_algorithm->length_secret_key);

  // Encapsulate
  status = KEM_encapsulate(&kem);
  if (status != 0) {
    fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
    KEM_destroy(&kem);
    return status;
  }
  // log8("encaps: ", kem.shared_secret, kem_algorithm->length_shared_secret);

  // Decapsulate
  status = KEM_decapsulate(&kem);
  if (status != 0) {
    fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
    KEM_destroy(&kem);
    return status;
  }
  log8("decaps: ", kem.shared_secret, kem_algorithm->length_shared_secret);
  printf("[heap] %s operations completed.\n", name);

  // Destroy all
  KEM_destroy(&kem);
  return 0;
}

int test_SIG(const char* name) {
  int status;
  // Create and init the SIG object
  SIG sig = SIG_create(name);
  OQS_SIG* sig_algorithm = get_sig_algorithm(sig.name);
  // [OPTIONAL] Generate private and public keys
  status = SIG_generate_keys(&sig);
  if (status != 0) {
    fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
    SIG_destroy(&sig);
    return status;
  }
  log8("pubKey: ", sig.public_key, sig_algorithm->length_public_key);
  log8("prvKey: ", sig.secret_key, sig_algorithm->length_secret_key);

  size_t len = 31;
  uint8_t msg[31] = {[0 ... 30] = 0x41};
  // Sign
  status = SIG_sign(&sig, msg, len);
  if (status != 0) {
    fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
    SIG_destroy(&sig);
    return status;
  }
  log8("signature: ", sig.signature, sig_algorithm->length_signature);

  // Verify
  // Note: no really need to create another sig, but when reusing the object,
  // setting the real sig_len is a MUST in variable signatures line Falcon.
  SIG sig2 = SIG_create(name);
  memcpy(sig2.public_key, sig.public_key, sig_algorithm->length_public_key);
  memcpy(sig2.signature, sig.signature, sig_algorithm->length_signature);
  sig2.signature_len =
      sig.signature_len;  // IMPORTANT! (only when using variable signature)
  status = SIG_verify(&sig2, msg, len);
  if (status != 0) {
    fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
    SIG_destroy(&sig);
    return status;
  }
  log8("verify: ", msg, len);
  printf("[heap] %s operations completed.\n", name);

  // Destroy all
  SIG_destroy(&sig);
  return 0;
}

int main(int argc, char const* argv[]) {
  const char* name = argc > 1 ? argv[1] : "Kyber768-90s";  // see kem.h
  test_KEM(name);
  return 0;
  // int s1 = test_KEM(KEM_NAMES.kyber3);
  //  int s2 = test_SIG(SIG_NAMES.falcon1);
  //  return s1 + s2;
}