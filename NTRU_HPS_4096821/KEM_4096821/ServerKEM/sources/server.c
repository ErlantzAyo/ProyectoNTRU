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

/* Symmetryc crypto */
#include "../../sparkle256/api.h"
#include "../../sparkle256/encrypt.c"  // hard included since encrypt.h is not in lib implementation
#include "../../sparkle256/sparkle_ref.h"
#define SPARKLE_MAX_SIZE 32

/*Benchmark*/

#include <time.h>

/* Parametros del servidor */
#define SERV_PORT 8080             /* puerto */
#define SERV_HOST_ADDR "127.0.0.1" /* IP  */
#define BUF_SIZE 1000              /* Buffer rx, tx max size  */
#define BACKLOG 5                  /* Max. client en espera de conectar  */

static void printBstr(const char *, const uint8_t *, size_t);
int KEM(int connfd, double *kpTime, double *decTime, uint8_t* shared_secret,
  int argc, char *argv[]);
double TiempoProceso(clock_t, clock_t);
void EscribirFichero(char *nombreFichero, char *variable, double dato);
static int decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *enc,
                   uint8_t *dec);
static void log8(char *text, uint8_t *data, size_t len);
void ReceiveSparkle256(int connfd, uint8_t* shared_secret);
void WriteFileKey(char *nombreFichero, uint8_t* key, size_t len);
void readFileKey(char *nombreFichero, uint8_t* key, size_t len);
void generateKeypair();

int main(int argc, char *argv[]) {
  int sockfd, connfd, n_conexion = 0; /* sockets*/
  unsigned int len;                   /* tamaño direccion de clietne */
  struct sockaddr_in servaddr, client;

  /* variables de tiempo de proceso*/
  double kpTime, decTime;

  uint8_t shared_secret[NTRU_SHAREDKEYBYTES];
  uint8_t msg[SPARKLE_MAX_SIZE];


  if (argc == 2 && strcmp(argv[1],"generate") == 0) {

    generateKeypair();
    exit(EXIT_SUCCESS);
  }
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

  /* acepta los datos provenientes de los sockets de manera interactiva */
  while (1) {
    connfd = accept(sockfd, (struct sockaddr *)&client, &len);
    if (connfd < 0) {
      fprintf(stderr, "[SERVER-error]: Conexion no aceptada %d: %s \n", errno,
              strerror(errno));
      return -1;
    } else {
      // KEM NTRU
//      for (int i = 0; i < 100; i++) {

       if(argc == 2 && strcmp(argv[1],"raw") == 0){

            read(connfd, msg, sizeof(msg));
            printf("Raw message: %s\n", msg);
            printf("\n");
          }
          else{

            printf("CONEXION %d:\n", ++n_conexion);
            EscribirFichero("../../datos.txt", "PRUEBA ", n_conexion);
            KEM(connfd, &kpTime, &decTime, shared_secret, argc, argv);
            ReceiveSparkle256(connfd,shared_secret);
            EscribirFichero("../../datos.txt", "KeypairTime (ms) =", kpTime);
            EscribirFichero("../../datos.txt", "DecryptTime (ms) =", decTime);
         }
//        }
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

int KEM(int connfd, double *kpTime, double *decTime, uint8_t* shared_secret,
  int argc, char *argv[]) {
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t secret_key[NTRU_SECRETKEYBYTES];
  uint8_t ciphertext[NTRU_CIPHERTEXTBYTES];

  int rc;

  clock_t tic, toc;

    //Case ./serverKEM key --> read keys from FILE.
  if(argc == 2 && strcmp(argv[1],"key") == 0){

    //WriteFileKey("../SK.bin",secret_key,sizeof(secret_key));
    //WriteFileKey("../PK.bin",public_key,sizeof(public_key));
    readFileKey("../SK.bin",secret_key,sizeof(secret_key));
    readFileKey("../PK.bin",public_key,sizeof(public_key));

  }else{
    tic = clock();
    rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(public_key, secret_key);
    toc = clock();
    *kpTime = TiempoProceso(tic, toc);
    if (rc != 0) {
      fprintf(stderr, "ERROR: crypto_kem_keypair failed!\n");
      return -1;
    }
  }
  //printBstr("SERVER: PK=", public_key, NTRU_PUBLICKEYBYTES);
  //printBstr("SERVER: SK=", secret_key,NTRU_SECRETKEYBYTES);
  write(connfd, public_key, sizeof(public_key));

  read(connfd, ciphertext, sizeof(ciphertext));

  printBstr("SERVER: CT=", ciphertext, NTRU_CIPHERTEXTBYTES);

  tic = clock();
  rc = PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec(shared_secret, ciphertext,
                                                   secret_key);
  toc = clock();
  *decTime = TiempoProceso(tic, toc);
  if (rc != 0) {
    fprintf(stderr, "ERROR: crypto_kem_dec failed!\n");
    return -3;
  }

  printBstr("SERVER: SSD=", shared_secret, NTRU_SHAREDKEYBYTES);
  printf("\n Keypair time (ms): %f ", *kpTime);
  printf("\n Decrypt time (ms): %f \n", *decTime);


  return 0;
}
void generateKeypair(){
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t secret_key[NTRU_SECRETKEYBYTES];

  PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair(public_key, secret_key);

  WriteFileKey("../SK.bin",secret_key,sizeof(secret_key));
  WriteFileKey("../PK.bin",public_key,sizeof(public_key));
  readFileKey("../SK.bin",secret_key,sizeof(secret_key));
  readFileKey("../PK.bin",public_key,sizeof(public_key));

}
void ReceiveSparkle256(int connfd, uint8_t* shared_secret){
  // Extract payload (nonce+encData)
  uint8_t nonce[SPARKLE_MAX_SIZE];
  read(connfd, nonce, sizeof nonce);
  uint8_t msg[SPARKLE_MAX_SIZE];
  read(connfd, msg, sizeof msg);
  log8("nonce: ", nonce, sizeof nonce);
  log8("enc  : ", msg, sizeof msg);
  decrypt(shared_secret, nonce, msg, msg);
  printf("dec: %s\n", msg);
  printf("\n");

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
void WriteFileKey(char *nombreFichero, uint8_t* key, size_t len) {
  FILE *fp;
  fp = fopen(nombreFichero, "w");

  if (fp == NULL) {
    printf("Error!");
    exit(1);
  }
  fwrite(key, 1,len,fp);
  fclose(fp);
}
void readFileKey(char *nombreFichero, uint8_t* key, size_t len) {
  FILE *fp;
  fp = fopen(nombreFichero, "r");

  if (fp == NULL) {
    printf("Error!");
    exit(1);
  }
  fread(key, 1,len,fp);
  printBstr("KEY IN FILE:", key, len);
  fclose(fp);
}


static int decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *enc,
                   uint8_t *dec) {
  SparkleState state = {{1}, {1}};
  // ARF: RND to prevent nonce misuse attacks
  // since we are not using encrypt as channel, nonce is not so important
  // randombytes(nonce, CRYPTO_KEYBYTES);
  Initialize(&state, key, nonce);
  ProcessCipherText(&state, dec, enc, SPARKLE_MAX_SIZE);
  return 0;
}

static void log8(char *text, uint8_t *data, size_t len) {
  // size_t LIMIT = len;
  size_t LIMIT = len < 32 ? len : 32;
  printf("%s", text);
  for (size_t r = 0; r < LIMIT; r++) printf("%02x", *data++);
  if (len > LIMIT) printf("...%zu bytes", len);
  printf("\n");
}
