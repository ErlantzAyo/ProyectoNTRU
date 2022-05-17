/*standard symbols */
#include <unistd.h>

/* sockets */
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

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
#include "randombytes.h"
#include "params.h"
#include "owcpa.h"

/*Benchmark*/

#include <time.h>

/* Parametros del servidor */
#define SERV_PORT       8080              /* puerto */
#define SERV_HOST_ADDR "127.0.0.1"     /* IP  */
#define BUF_SIZE        1000              /* Buffer rx, tx max size  */
#define BACKLOG         5                 /* Max. client en espera de conectar  */


static void printBstr(const char *, const uint8_t *, size_t);
double TiempoProceso(clock_t, clock_t);
void EscribirFichero(char* nombreFichero, char* variable, double dato);
void Asymetric_NTRU_HRSS701_Server(int sockfd);
static void unpack_message(poly *r, poly *m, const unsigned char *message);

int main(int argc, char* argv[]) {

    int sockfd, connfd, n_conexion = 0; /* sockets*/
    unsigned int len; /* tamaño direccion de clietne */
    struct sockaddr_in servaddr, client;

    /* variables de tiempo de proceso*/
    //double kpTime,decTime;



    /* creacion de socket*/
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "[SERVER-error]: Error creando el servidor. %d: %s \n", errno, strerror(errno));
        return -1;
    } else {
        printf("[SERVER]: Socket creado corectamente..\n");
    }

    memset(&servaddr, 0, sizeof (servaddr));

    /* asignar IP, SERV_PORT, IPV4 */
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    servaddr.sin_port = htons(SERV_PORT);


    /* Bind socket */
    if ((bind(sockfd, (struct sockaddr *) &servaddr, sizeof (servaddr))) != 0) {
        fprintf(stderr, "[SERVER-error]: Error bind. %d: %s \n", errno, strerror(errno));
        return -1;
    } else {
        printf("[SERVER]: Socket bind correcto \n");
    }

    /* Listen */
    if ((listen(sockfd, BACKLOG)) != 0) {
        fprintf(stderr, "[SERVER-error]: Error en socket a la escucha. %d: %s \n", errno, strerror(errno));
        return -1;
    } else {
        printf("[SERVER]: Escuchando en SERV_PORT %hu \n\n", ntohs(servaddr.sin_port));
    }

    len = sizeof (client);

    /* acepta los datos provenientes de los seocket de manera interacitiva */
    while (1) {
        connfd = accept(sockfd, (struct sockaddr *) &client, &len);
        if (connfd < 0) {
            fprintf(stderr, "[SERVER-error]: Conexion no aceptada %d: %s \n", errno, strerror(errno));
            return -1;
        } else {

            // KEM NTRU
            //for(int i=0; i<10; i++){
                 printf("CONEXION %d:\n", ++n_conexion);
	        // EscribirFichero("../../datos.txt","PRUEBA ",n_conexion);
           Asymetric_NTRU_HRSS701_Server(connfd);

           		close(connfd);

            //     EscribirFichero("../../datos.txt","KeypairTime (ms) =",kpTime);
            //     EscribirFichero("../../datos.txt","DecryptTime (ms) =",decTime);

            // }
        }
    }

}

/* while (1)  {

                len_rx = read(connfd, buff_rx, sizeof (buff_rx));

                if (len_rx == -1) {
                    fprintf(stderr, "[SERVER-error]: connfd cannot be read. %d: %s \n", errno, strerror(errno));
                } else if (len_rx == 0) {
                    printf("[SERVER]: client socket closed \n\n");
                    close(connfd);
                    break;
                } else {
                    write(connfd, buff_tx, sizeof(buff_tx));
                    printf("[SERVER]: %s \n", buff_rx);
                }
            } */

void Asymetric_NTRU_HRSS701_Server(int sockfd){
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t secret_key[NTRU_SECRETKEYBYTES];
  uint8_t cyphertext[NTRU_CIPHERTEXTBYTES];
  uint8_t rm[NTRU_OWCPA_MSGBYTES];// o NTRU_SAMPLE_RM_BYTES?
  uint8_t msg[NTRU_SAMPLE_RM_BYTES];

  poly m,r;
  int rc;
rc = PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_keypair(public_key,secret_key);

    printBstr("\nPK = ", public_key, sizeof public_key);
  write(sockfd, public_key, sizeof(public_key));
  read(sockfd, cyphertext, sizeof(cyphertext));

  PQCLEAN_NTRUHRSS701_CLEAN_owcpa_dec(rm, cyphertext, secret_key);
  printBstr("\nTExto Cifrado = ", cyphertext, sizeof(cyphertext));
  unpack_message(&r, &m, rm);
  printf("\n NTRU_OWCPA_MSGBYTES: %d \n",NTRU_OWCPA_BYTES);
    printf("\n NTRU_SAMPLE_RM_BYTES: %d \n",NTRU_SAMPLE_RM_BYTES);
  PQCLEAN_NTRUHRSS701_CLEAN_poly_S3_tobytes(msg,&m);

  printf("\nMENSAJE: %s \n", msg);

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

    double elapsed = (double) (toc - tic) * 1000.0 / CLOCKS_PER_SEC;

    return elapsed;
}

void EscribirFichero(char* nombreFichero, char* variable, double dato) {


    FILE * fp;
    fp = fopen(nombreFichero, "a");

    if (fp == NULL) {
        printf("Error!");
        exit(1);
    }


    fprintf(fp, "%s %f\n", variable,dato);
    fclose(fp);
}

static void unpack_message(poly *r, poly *m, const unsigned char *message) {
    PQCLEAN_NTRUHRSS701_CLEAN_poly_S3_frombytes(r, message);
    PQCLEAN_NTRUHRSS701_CLEAN_poly_S3_frombytes(m, message + NTRU_PACK_TRINARY_BYTES);
}
