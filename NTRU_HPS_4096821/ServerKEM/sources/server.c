/*standard symbols */
#include <unistd.h>

/* sockets */
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/* strings / errors*/
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
/*KEM*/

#include "api.h"
#include "params.h"
#include "randombytes.h"

/* Symmetryc crypto */
#include "../../sparkle256/api.h"
#include "../../sparkle256/encrypt.c"  // hard included since encrypt.h is not in lib implementation
#include "../../sparkle256/sparkle_ref.h"

/*Benchmark*/
#include <time.h>
/*File management*/
#include "file_io.h"
/*Utils*/
#include "utils.h"

/* Parametros del servidor */
#define SERV_PORT 8080             /* puerto */
#define SERV_HOST_ADDR "127.0.0.1" /* IP  */
#define BUF_SIZE 1000              /* Buffer rx, tx max size  */
#define BACKLOG 5                  /* Max. client en espera de conectar  */


#define HELP                                                   \
  "\nPost-Quantum client.\n\n"                                 \
  "Usage:\n"                                                   \
  "  (no params) - Create server with localhost address at 8080 port\n" \
  "  raw         - Do not encrypt (useful for benchmarking)\n" \

int KEM(int connfd, uint8_t *shared_secret);
static int decrypt(const uint8_t *id, const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *tag, uint8_t *ct, const size_t ct_len,
                   uint8_t *msg);
void ReceiveSparkle256(int connfd, uint8_t *shared_secret);
void generateKeypair();
int start(int argc, char *argv[]);

int main(int argc, char *argv[]) {

  if (argc < 2) return start(argc, argv);

  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "help") == 0) {
    return printf(HELP);
  }else {
    return start(argc, argv);
  }
}

int start(int argc, char *argv[]) {

  int sockfd, connfd; /* sockets*/
  unsigned int len;                   /* tamaño direccion de clietne */
  struct sockaddr_in servaddr, client;
  /* variables de tiempo de proceso*/
  double kpTime, decTime;

  uint8_t shared_secret[NTRU_SHAREDKEYBYTES];
  uint8_t msg[CRYPTO_KEYBYTES];

  // generate PK SK keys ande SAVES on FILE
  generateKeypair();

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
  int n=0;

  /* acepta los datos provenientes de los sockets de manera interactiva */
  while (1) {
    connfd = accept(sockfd, (struct sockaddr *)&client, &len);
    if (connfd < 0) {
      fprintf(stderr, "[SERVER-error]: Conexion no aceptada %d: %s \n", errno,
              strerror(errno));
      return -1;
    } else {
      if (argc == 2 && strcmp(argv[1], "raw") == 0) {
        read(connfd, msg, sizeof(msg));
        printf("Raw message: %s\n", msg);
        printf("\n");
      } else {

        EscribirFichero("../../datos.txt", "PRUEBA ", connfd);
        KEM(connfd, shared_secret);
        ReceiveSparkle256(connfd, shared_secret);
        printf("Conexion : %d\n", n++);
          close(connfd);
      }
    }
  }

  close(sockfd);




  return 0;

}
int KEM(int connfd, uint8_t *shared_secret) {
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t secret_key[NTRU_SECRETKEYBYTES];
  uint8_t ciphertext[NTRU_CIPHERTEXTBYTES];

  int rc;


  // Case ./serverKEM key --> read keys from FILE.
  readFileKey("../SK.pem", secret_key, sizeof(secret_key));
  //SprintBstr("READ SECRET KEY = ", secret_key, sizeof secret_key);
  readFileKey("../PK.pem", public_key, sizeof(public_key));
  //printBstr("READ PUBLIC KEY = ", secret_key, sizeof secret_key);

  write(connfd, public_key, sizeof(public_key));

  read(connfd, ciphertext, sizeof(ciphertext));

  printBstr("SERVER: CT=", ciphertext, NTRU_CIPHERTEXTBYTES);

  rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec(shared_secret, ciphertext,
                                                   secret_key);

  if (rc != 0) {
    fprintf(stderr, "ERROR: crypto_kem_dec failed!\n");
    return -3;
  }

  printBstr("SERVER: SSD=", shared_secret, NTRU_SHAREDKEYBYTES);


  return 0;
}
void generateKeypair() {
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t secret_key[NTRU_SECRETKEYBYTES];

  PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(public_key, secret_key);
  WriteFileKey("../SK.pem", secret_key, sizeof(secret_key));
  WriteFileKey("../PK.pem", public_key, sizeof(public_key));
}

void ReceiveSparkle256(int connfd, uint8_t *shared_secret) {
  // Extract payload (nonce+encData+tag)
  uint8_t nonce[CRYPTO_KEYBYTES];
  read(connfd, nonce, sizeof nonce);
  uint8_t msg[CRYPTO_KEYBYTES];
  read(connfd, msg, sizeof msg);
  uint8_t tag[CRYPTO_KEYBYTES];
  read(connfd, tag, sizeof tag);
  log8("nonce: ", nonce, sizeof nonce);
  log8("enc  : ", msg, sizeof msg);
  log8("tag  : ", tag, sizeof tag);

  /* Id of client */
  // ARF to ERL: this ID could be provided when client connects, but we can keep
  // it as secondary secure key for now (because in the current case, the ID is
  // not sent)
  uint8_t id[CRYPTO_KEYBYTES] = {0};
  char *name = "RASPBERRY_1";
  memcpy(id, name, strlen(name));

  int status = decrypt(id, shared_secret, nonce, tag, msg, sizeof msg, msg);
  if (status != 0) printf("Error on decryption: status=%i", status);
  printf("dec: %s\n", msg);
  printf("\n");
}

static int decrypt(const uint8_t *id, const uint8_t *key, const uint8_t *nonce,
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
