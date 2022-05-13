/*standard symbols */
#include <unistd.h>

/* sockets */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/* strings / errors*/
#include <errno.h>
#include <stdio.h>
#include <string.h>

/*KEM*/

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "api.h"
#include "params.h"
#include "randombytes.h"

/*Benchmark*/

#include <time.h>

/* Parametros del servidor */
#define SERV_PORT 8080             /* puerto */
#define SERV_HOST_ADDR "127.0.0.1" /* IP  */
#define BUF_SIZE 1000              /* Buffer rx, tx max size  */
#define BACKLOG 5                  /* Max. client en espera de conectar  */

static void printBstr(const char *, const uint8_t *, size_t);
int KEM(int, double *, double *);
double TiempoProceso(clock_t, clock_t);
void EscribirFichero(char *nombreFichero, char *variable, double dato);

int main(int argc, char *argv[]) {
  int sockfd, connfd, n_conexion = 0; /* sockets*/
  unsigned int len;                   /* tamaño direccion de clietne */
  struct sockaddr_in servaddr, client;

  /* variables de tiempo de proceso*/
  double kpTime, decTime;

  /* creacion de socket*/
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    fprintf(stderr, "[SERVER-error]: Error creando el servidor. %d: %s \n",
            errno, strerror(errno));
    return -1;
  } else {
    printf("[SERVER]: Socket creado corectamente..\n");
  }

  memset(&servaddr, 0, sizeof(servaddr));

  /* asignar IP, SERV_PORT, IPV4 */
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
  servaddr.sin_port = htons(SERV_PORT);

  /* Bind socket */
  if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
    fprintf(stderr, "[SERVER-error]: Error bind. %d: %s \n", errno,
            strerror(errno));
    return -1;
  } else {
    printf("[SERVER]: Socket bind correcto \n");
  }

  /* Listen */
  if ((listen(sockfd, BACKLOG)) != 0) {
    fprintf(stderr, "[SERVER-error]: Error en socket a la escucha. %d: %s \n",
            errno, strerror(errno));
    return -1;
  } else {
    printf("[SERVER]: Escuchando en SERV_PORT %hu \n\n",
           ntohs(servaddr.sin_port));
  }

  len = sizeof(client);

  /* acepta los datos provenientes de los seocket de manera interactiva */
  while (1) {
    connfd = accept(sockfd, (struct sockaddr *)&client, &len);
    if (connfd < 0) {
      fprintf(stderr, "[SERVER-error]: Conexion no aceptada %d: %s \n", errno,
              strerror(errno));
      return -1;
    } else {
      // KEM NTRU
      for (int i = 0; i < 100; i++) {
        printf("CONEXION %d:\n", ++n_conexion);
        EscribirFichero("../../datos.txt", "PRUEBA ", n_conexion);
        KEM(connfd, &kpTime, &decTime);
        EscribirFichero("../../datos.txt", "KeypairTime (ms) =", kpTime);
        EscribirFichero("../../datos.txt", "DecryptTime (ms) =", decTime);
      }
      close(connfd);
    }
  }
}

/* while (1)  {

                len_rx = read(connfd, buff_rx, sizeof (buff_rx));

                if (len_rx == -1) {
                    fprintf(stderr, "[SERVER-error]: connfd cannot be read. %d:
   %s \n", errno, strerror(errno)); } else if (len_rx == 0) { printf("[SERVER]:
   client socket closed \n\n"); close(connfd); break; } else { write(connfd,
   buff_tx, sizeof(buff_tx)); printf("[SERVER]: %s \n", buff_rx);
                }
            } */

int KEM(int connfd, double *kpTime, double *decTime) {
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t secret_key[NTRU_SECRETKEYBYTES];
  uint8_t ciphertext[NTRU_CIPHERTEXTBYTES];
  uint8_t shared_secret_d[NTRU_SHAREDKEYBYTES];
  int rc;

  clock_t tic, toc;

  tic = clock();
  rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(public_key, secret_key);
  toc = clock();
  *kpTime = TiempoProceso(tic, toc);
  if (rc != 0) {
    fprintf(stderr, "ERROR: crypto_kem_keypair failed!\n");
    return -1;
  }

  printBstr("SERVER: PK=", public_key, NTRU_PUBLICKEYBYTES);
  // printBstr("SERVER: SK=", secret_key,NTRU_SECRETKEYBYTES);
  write(connfd, public_key, sizeof(public_key));

  read(connfd, ciphertext, sizeof(ciphertext));

  printBstr("SERVER: CT=", ciphertext, NTRU_CIPHERTEXTBYTES);

  // ARF
  char data[32];
  read(connfd, data, sizeof data);
  printf("SERVER: VALUE=%s\n\n", data);

  tic = clock();
  rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec(shared_secret_d, ciphertext,
                                                   secret_key);
  toc = clock();
  *decTime = TiempoProceso(tic, toc);
  if (rc != 0) {
    fprintf(stderr, "ERROR: crypto_kem_dec failed!\n");
    return -3;
  }

  printBstr("SERVER: SSD=", shared_secret_d, NTRU_SHAREDKEYBYTES);
  printf("\n Keypair time (ms): %f ", *kpTime);
  printf("\n Decrypt time (ms): %f \n", *decTime);
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
