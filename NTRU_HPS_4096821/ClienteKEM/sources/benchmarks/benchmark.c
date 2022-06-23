/*************************************************************************************
 *                              Benchmark for CPU and NET
 *
 * Usage :See the help string in this file.
 *
 *************************************************************************************/
/**
 * These defines
 */
#ifndef BENCH_MAX
#define BENCH_MAX 10000
#endif
#ifndef BENCH_MAX_NET
#define BENCH_MAX_NET 1000
#endif

/*standard symbols */
#include <unistd.h>

/* sockets */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/* strings / errors*/
#include <errno.h>
#include <stdio.h>
#include <string.h>

/*KEM*/
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "aes.h"
#include "api.h"
#include "file_io.h"
#include "params.h"
#include "randombytes.h"

/* Symmetryc crypto */
#include "../../sparkle256/api.h"
#include "../../sparkle256/encrypt.c"  // hard included since encrypt.h is not in lib implementation
#include "../../sparkle256/sparkle_ref.h"

/*Benchmark*/
#include <time.h>
/*Utils*/
#include "utils.h"
/*File management*/
#include "file_io.h"

/* Parametros del cliente */
static char SERVER_ADDRESS[30] = "127.0.0.1"; /* IP address */
static int PORT = 8080;                       /* Port */
static uint8_t public_key[NTRU_PUBLICKEYBYTES];

#define HELP                                                   \
  "\nPost-Quantum client.\n\n"                                 \
  "Usage:\n"                                                   \
  "  (no params) - Connect to localhost server at 8080 port\n" \
  "  raw         - Do not encrypt (useful for benchmarking)\n" \
  "  $ip $port     - Connect to another server or port\n"

int KEMCliente(int, double *, uint8_t *);
int serverInfo();
int encrypt(const uint8_t *id, const uint8_t *key, const uint8_t *msg,
            const size_t msg_len, uint8_t *nonce, uint8_t *tag, uint8_t *ct);

void sendSparkle256(int sockfd, uint8_t *shared_secret, uint8_t *msg);
int start(int argc, char *argv[]);

int mainOLD(int argc, char *argv[]) {
  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "help") == 0))
    return OUTPUT((HELP));

  if (argc >= 2 && strcmp(argv[1], "raw") != 0) {
    strcpy(SERVER_ADDRESS, argv[1]);
    if (argc > 2) PORT = atoi(argv[2]);
  }
#ifdef PRODUCTION
  while (true) {
    start(argc, argv);
    sleep(10);
  }
#else
  for (int i = 0; i < 1000; i++) {
    start(argc, argv);
  }
#endif
}

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

int benchmarkNETWORK(int argc, char const *argv[]) {
  // server addr & port (default: localhost 8080)
  if (argc >= 2 && strcmp(argv[1], "raw") != 0) {
    strcpy(SERVER_ADDRESS, argv[1]);
    if (argc > 2) PORT = atoi(argv[2]);
  }

  // execute all
  uint64_t t1, t2;
  t1 = currentTimeMillis();
  int status;
  for (int i = 0; i < BENCH_MAX_NET; i++) {
    status = start(argc, argv);
    if (status != 0) return status;
  }

  // check server if processed all interations
  // status = serverInfo();
  // if (status != 0) return status;

  // measure
  t2 = currentTimeMillis();
  printf("\nNETWORK: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX_NET);
  return 0;
}

int benchmarkNTRU() {
  printf(
      "\n--- ASYMMETRIC NTRU-HPS-4096-821_ref (level V and no CPU extensions) "
      "---\n");
  size_t pkl = NTRU_PUBLICKEYBYTES;
  size_t skl = NTRU_PUBLICKEYBYTES;
  size_t ctl = NTRU_CIPHERTEXTBYTES;
  size_t ssl = NTRU_SECRETKEYBYTES;
  uint8_t pk[NTRU_PUBLICKEYBYTES];
  uint8_t sk[NTRU_SECRETKEYBYTES];
  readFileKey("../../ServerKEM/PK.pem", pk, pkl);
  readFileKey("../../ServerKEM/SK.pem", sk, skl);
  uint8_t res[BENCH_MAX] = {0};
  size_t pos = 0;
  uint8_t ct[NTRU_CIPHERTEXTBYTES];
  uint8_t ss[NTRU_SHAREDKEYBYTES];
  int status;
  uint64_t t1, t2;

  //--------------KeyGen-------------------
  int BENCH_MAX_KEYGEN = BENCH_MAX / 100;
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX_KEYGEN; r++) {
    status = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(pk, sk);
    if (status != 0) return 1;
    res[r] = sk[pos] + pk[pos];
    pos++;
    if (pos > skl) pos = 0;
  }
  t2 = currentTimeMillis();
  printf("KEYGEN: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX_KEYGEN);

  //--------------Encaps-------------------
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX; r++) {
    status = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc(ct, ss, pk);
    if (status != 0) return 1;
    res[r] = ct[pos++];
    if (pos > ctl) pos = 0;
  }
  t2 = currentTimeMillis();
  printf("ENCAPS: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX);

  //--------------Decaps-------------------
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX; r++) {
    status = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec(ss, ct, sk);
    if (status != 0) return 1;
    res[r] = ss[pos++];
    if (pos > ssl) pos = 0;
  }
  t2 = currentTimeMillis();
  printf("DECAPS: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX);

  //---dump data to prevent never-used optimization---
  log8("RES: ", res, BENCH_MAX);
  return status;
}

int benchmarkSPARKLE() {
  printf(
      "\n--- SYMMETRIC SPARKLE-256_ref (level V, aead mode and no CPU "
      "extensions) ---\n");
  int status = 0;
  uint64_t t1, t2;
  uint8_t *id = "aaaaaaaaaaaaa";
  uint8_t *txt = "hoola";
  size_t len = 32;
  uint8_t *msg = calloc(1, len);
  memcpy(msg, txt, len);
  uint8_t key[32] = {66};
  uint8_t nonce[32];
  uint8_t tag[32];
  uint8_t *ct = calloc(1, len);

  //--------------Encrypt------------------
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX; r++) {
    *msg = *msg + 1;
    status = encrypt(id, key, msg, len, nonce, tag, ct);
    if (status != 0) return 1;
  }
  t2 = currentTimeMillis();
  printf("ENCRYPT: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX);

  //--------------Decrypt------------------
  t1 = currentTimeMillis();
  for (int r = 0; r < BENCH_MAX; r++) {
    //*ct = *ct + 1; //TODO check dec speed optimized (same ct same nonce, etc)
    status = decrypt(id, key, nonce, tag, ct, len, msg);
    if (status != 0) return 1;
  }
  t2 = currentTimeMillis();
  printf("DECRYPT: %lf ms/op\n", (t2 - t1) * 1.0 / BENCH_MAX);
  log8("RES: ", msg, len);
  return status;
}

int start(int argc, char *argv[]) {
  int sockfd;
  struct sockaddr_in servaddr;

  double encTime;
  uint8_t shared_secret[NTRU_SHAREDKEYBYTES];
  /* Socket creation */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  printf("\n");
  if (sockfd == -1) {
    OUTPUT(("CLIENT: socket creation failed...\n"));
    return -1;
  } else {
    OUTPUT(("CLIENT: Socket successfully created..\n"));
  }

  memset(&servaddr, 0, sizeof(servaddr));

  /* assign IP, PORT */
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
  servaddr.sin_port = htons(PORT);

  /* try to connect the client socket to server socket */
  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
    OUTPUT(("connection with the server failed...\n"));
    return -1;
  }

  OUTPUT(("connected to the server..\n"));

  // read PK
  read(sockfd, public_key, sizeof(public_key));
  printBstr("CLIENT: PK=", public_key, NTRU_CIPHERTEXTBYTES);

  // send data

  if (argc == 2 && strcmp(argv[1], "raw") == 0) {
    uint8_t msg[CRYPTO_KEYBYTES];
    getTempMsg(msg);
    write(sockfd, msg, sizeof(msg));
  } else {
    KEMCliente(sockfd, &encTime, shared_secret);
    EscribirFichero("../../datos.txt", "EncryptTime (ms) =", encTime);
  }
  /* close the socket */
  close(sockfd);

  return 0;
}

int KEMCliente(int sockfd, double *encTime, uint8_t *shared_secret) {
  uint8_t ciphertext[NTRU_CIPHERTEXTBYTES];
  int rc;
  clock_t tic, toc;
  tic = clock();
  rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc(ciphertext, shared_secret,
                                                   public_key);
  toc = clock();
  *encTime = TiempoProceso(tic, toc);
  if (rc != 0) {
    fprintf(stderr, "ERROR: crypto_kem_enc failed!\n");
    return -2;
  }
  // printBstr("CLIENT: CT=", ciphertext, NTRU_CIPHERTEXTBYTES);
  printBstr("CLIENT: SSE=", shared_secret, NTRU_SHAREDKEYBYTES);

  write(sockfd, ciphertext, sizeof(ciphertext));

  // Gather and transmit encryptedsensor data
  uint8_t msg[CRYPTO_KEYBYTES];
  getTempMsg(msg);
  sendSparkle256(sockfd, shared_secret, msg);
  return 0;
}

void sendSparkle256(int sockfd, uint8_t *shared_secret, uint8_t *msg) {
  /* ID for authentication */
  uint8_t id[CRYPTO_KEYBYTES] = {0};
  char *name = "RASPBERRY_1";
  memcpy(id, name, strlen(name));

  /* Nonce management */
  uint8_t nonce[CRYPTO_KEYBYTES];
  randombytes(nonce, CRYPTO_KEYBYTES);  // not a nonce but secure and clean
  int checkRNG = 0;
  for (int r = 0; r < sizeof(nonce); r++) checkRNG += nonce[r];
  if (checkRNG == 0) {
    fprintf(stderr, "CRITICAL: RNG is not enabled");
    exit(500);  // CRITICAL: RNG generator not enabled
  }

  /* Encrypt and generate tag*/
  uint8_t tag[CRYPTO_KEYBYTES];
  uint8_t enc[CRYPTO_KEYBYTES];
  encrypt(id, shared_secret, msg, CRYPTO_KEYBYTES, nonce, tag, enc);
  log8("nonce: ", nonce, sizeof nonce);
  log8("enc  : ", enc, sizeof enc);
  log8("tag  : ", tag, sizeof tag);

  /* Send to socket */
  write(sockfd, nonce, CRYPTO_KEYBYTES);
  write(sockfd, enc, CRYPTO_KEYBYTES);
  write(sockfd, tag, CRYPTO_KEYBYTES);
}

int encrypt(const uint8_t *id, const uint8_t *key, const uint8_t *msg,
            const size_t msg_len, uint8_t *nonce, uint8_t *tag, uint8_t *ct) {
  SparkleState state;
  Initialize(&state, key, nonce);
  if (id != NULL) ProcessAssocData(&state, id, CRYPTO_KEYBYTES);
  ProcessPlainText(&state, ct, msg, msg_len);
  Finalize(&state, key);
  if (id != NULL) GenerateTag(&state, tag);
  return 0;
}

int decrypt(const uint8_t *id, const uint8_t *key, const uint8_t *nonce,
            const uint8_t *tag, uint8_t *ct, const size_t ct_len,
            uint8_t *msg) {
  int status = 0;
  SparkleState state;
  Initialize(&state, key, nonce);
  if (id != NULL) ProcessAssocData(&state, id, CRYPTO_KEYBYTES);
  ProcessCipherText(&state, msg, ct, ct_len);
  Finalize(&state, key);
  if (id != NULL) status = VerifyTag(&state, tag);
  return status;
}

int serverInfo() {
  // Connect to server and send "info"
  // The server will return then number of connections
  // retrieved AND processed on its side.

  // TODO: disabled by now because server process will be fast
  // so real difference between last TCP ack and return info will not be
  // relevant to the total time.
}

int main(int argc, char const *argv[]) {
  if (argc == 1) {
    printf(
        " Usage: ./benchmark addr port\n\n"
        "[OPTIONAL] Use -DBENCH_MAX and -DBENCH_MAX_NET to change default "
        "values during compilation\n");
    return 0;
  }
  warmCPU();
  if (benchmarkNTRU() != 0) printf("@@@@ INVALID NTRU BENCHMARK@@@ \n");
  if (benchmarkSPARKLE() != 0) printf("@@@@ INVALID SPARKLE BENCHMARK@@@ \n");
  if (benchmarkNETWORK(argc, argv) != 0)
    printf("@@@@ INVALID NETWOK BENCHMARK@@@ \n");
  return 0;
}
