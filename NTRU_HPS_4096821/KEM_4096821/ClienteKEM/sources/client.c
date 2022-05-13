/*************************************************************************************/
/* @file    cliente.c */
/* @brief   This clients connects, */
/*          sends a text, reads what server and disconnects */
/*************************************************************************************/

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

/*ARF crypto*/
#include "../../sparkle256/api.h"
#include "../../sparkle256/encrypt.c"  // hard included since encrypt.h is not in lib implementation
#include "../../sparkle256/sparkle_ref.h"
#define SPARKLE_MAX_SIZE 32
/*Benchmark*/
#include <time.h>

/* Parametros del cliente */
#define SERVER_ADDRESS "127.0.0.1" /* Direccion IP */
#define PORT 8080                  /* puerto */

int KEMCliente(int, double *);
static void printBstr(const char *, const uint8_t *, size_t);
double TiempoProceso(clock_t, clock_t);
void EscribirFichero(char *, char *, double);
static int encrypt(const uint8_t *key, const uint8_t *dec, uint8_t *enc);

int main() {
  int sockfd;
  struct sockaddr_in servaddr;

  double encTime;

  /* Socket creation */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    printf("CLIENT: socket creation failed...\n");
    return -1;
  } else {
    printf("CLIENT: Socket successfully created..\n");
  }

  memset(&servaddr, 0, sizeof(servaddr));

  /* assign IP, PORT */
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
  servaddr.sin_port = htons(PORT);

  /* try to connect the client socket to server socket */
  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
    printf("connection with the server failed...\n");
    return -1;
  }

  printf("connected to the server..\n");

  //for (int i = 0; i < 100; i++) {
    KEMCliente(sockfd, &encTime);
    EscribirFichero("../../datos.txt", "EncryptTime (ms) =", encTime);
  //}

  /* close the socket */
  close(sockfd);
}

int KEMCliente(int sockfd, double *encTime) {
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t ciphertext[NTRU_CIPHERTEXTBYTES];
  uint8_t shared_secret_e[NTRU_SHAREDKEYBYTES];
  int rc;
  clock_t tic, toc;

  read(sockfd, public_key, sizeof(public_key));

  printBstr("CLIENT: PK=", public_key, NTRU_CIPHERTEXTBYTES);
  tic = clock();
  rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc(ciphertext, shared_secret_e,
                                                   public_key);
  toc = clock();
  *encTime = TiempoProceso(tic, toc);
  if (rc != 0) {
    fprintf(stderr, "ERROR: crypto_kem_enc failed!\n");
    return -2;
  }
  printBstr("CLIENT: CT=", ciphertext, NTRU_CIPHERTEXTBYTES);
  printBstr("CLIENT: SSE=", shared_secret_e, NTRU_SHAREDKEYBYTES);

  write(sockfd, ciphertext, sizeof(ciphertext));

  // ARF- send also the encrypted data
  uint8_t *dec = (uint8_t *)"Temp:25.5";
  uint8_t enc[SPARKLE_MAX_SIZE];
  encrypt(shared_secret_e, dec, enc);
  write(sockfd, enc, SPARKLE_MAX_SIZE);
  // end ARF

  return 0;
}

static void printBstr(const char *S, const uint8_t *key, size_t L) {
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

void EscribirFichero(char *nombreFichero, char *variable, double dato) {
  FILE *fp;
  fp = fopen(nombreFichero, "a");

  if (fp == NULL) {
    printf("Error!");
    exit(1);
  }

  fprintf(fp, "%s %f\n", variable, dato);
  fclose(fp);
}

static int encrypt(const uint8_t *key, const uint8_t *dec, uint8_t *enc) {
  // SPARKLE EXAMPLE
  SparkleState state = {{1}, {1}};
  const uint8_t nonce[CRYPTO_KEYBYTES] = {1};  // ARF: TODO CHANGE TO RND
  Initialize(&state, key, nonce);
  ProcessPlainText(&state, enc, dec, SPARKLE_MAX_SIZE);
  printBstr("enc:", enc, SPARKLE_MAX_SIZE);
  ProcessCipherText(&state, enc, dec, SPARKLE_MAX_SIZE);
  printf("dec: %s\n", dec);
  return 0;
  // AES EXAMPLE (not working yet)
  //  char data[32] = "hooola";
  //  uint8_t out[32];
  //  uint8_t iv[32] = {0};
  //  uint8_t key[32] = {1};
  //  aes256ctx ctx;
  //  void aes256_ctr_keyexp(&ctx, key);
  //  void aes256_ctx_release(aes256ctx * r);
  //   void aes256_ctr_keyexp(aes256ctx *r, const unsigned char *key);

  // void aes256_ctr(out, 32, iv, const aes256ctx *ctx);
}
