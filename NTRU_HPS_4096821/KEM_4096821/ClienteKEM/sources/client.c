/*************************************************************************************
 * @file    cliente.c
 * @brief   This clients connects,
 *          sends a text, reads what server and disconnects
 *
 * Note: use __PRODUCTION__ flag for continuous mode
 * Note: use __BENCH__ flag for no printf mode (for benchmarks)
 *************************************************************************************/

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

int encrypt(const uint8_t *id, const uint8_t *key, const uint8_t *msg,
            const size_t msg_len, uint8_t *nonce, uint8_t *tag, uint8_t *ct);

void sendSparkle256(int sockfd, uint8_t *shared_secret, uint8_t *msg);
int start(int argc, char *argv[]);

int main(int argc, char *argv[]) {
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
  for (int i = 0; i < 100; i++) {
    start(argc, argv);
  }
#endif
}

int start(int argc, char *argv[]) {
  int sockfd;
  struct sockaddr_in servaddr;

  double encTime;
  uint8_t shared_secret[NTRU_SHAREDKEYBYTES];
  /* Socket creation */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
