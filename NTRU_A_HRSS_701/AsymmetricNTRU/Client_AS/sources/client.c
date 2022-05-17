/*************************************************************************************/
/* @file    cliente.c                                                               */
/* @brief   This clients connects,                                                   */
/*          sends a text, reads what server and disconnects                          */
/*************************************************************************************/


/*standard symbols */
#include <unistd.h>

/* sockets */
#include <netdb.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* strings / errors*/
#include <string.h>
#include <stdio.h>
#include <errno.h>

/*KEM*/
#include <assert.h>

#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "api.h"
#include "randombytes.h"
#include "params.h"
#include "owcpa.h"
#include "sample.h"

/*Benchmark*/
#include <time.h>

/* Parametros del cliente */
#define SERVER_ADDRESS  "127.0.0.1"     /* Direccion IP */
#define PORT            8080 		/* puerto */


static void printBstr( const char *, const uint8_t *, size_t);
double TiempoProceso(clock_t, clock_t);
void EscribirFichero(char*, char*, double);
void Asymetric_NTRU_HRSS701_Client(int sockfd);

int main()
{
    int sockfd;
    struct sockaddr_in servaddr;

    //double encTime;

    /* Socket creation */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("CLIENT: socket creation failed...\n");
        return -1;
    }
    else
    {
        printf("CLIENT: Socket successfully created..\n");
    }


    memset(&servaddr, 0, sizeof(servaddr));

    /* assign IP, PORT */
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr( SERVER_ADDRESS );
    servaddr.sin_port = htons(PORT);

    /* try to connect the client socket to server socket */
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
    {
        printf("connection with the server failed...\n");
        return -1;
    }

    printf("connected to the server..\n");

    //for(int i=0; i<10; i++){


      Asymetric_NTRU_HRSS701_Client(sockfd);


        //EscribirFichero("../../datos.txt","EncryptTime (ms) =",encTime);

    //}

    /* close the socket */
    close(sockfd);
}

void Asymetric_NTRU_HRSS701_Client(int sockfd){
  uint8_t public_key[NTRU_PUBLICKEYBYTES];
  uint8_t cyphertext[NTRU_CIPHERTEXTBYTES];
  uint8_t msg[NTRU_SAMPLE_RM_BYTES]="HOLA QUE TAL?";
  uint8_t buzz[NTRU_SAMPLE_IID_BYTES];

  poly m,r;

    uint8_t m1[NTRU_SAMPLE_RM_BYTES];

  read(sockfd, public_key, sizeof(public_key));
  printBstr("\nPK = ", public_key, sizeof public_key);

  randombytes(buzz,NTRU_SAMPLE_IID_BYTES);
  PQCLEAN_NTRUHRSS701_CLEAN_sample_iid(&r,buzz);
  PQCLEAN_NTRUHRSS701_CLEAN_poly_Z3_to_Zq(&r);
  PQCLEAN_NTRUHRSS701_CLEAN_poly_S3_frombytes(&m,msg);

  PQCLEAN_NTRUHRSS701_CLEAN_poly_S3_tobytes(m1,&m);
      printf("\nMENSAJE M1: %s", m1);

  PQCLEAN_NTRUHRSS701_CLEAN_owcpa_enc(cyphertext, &r, &m, public_key);
  printBstr("\nTExto Cifrado = ", cyphertext, sizeof(cyphertext));
  write(sockfd, cyphertext, sizeof(cyphertext));



}



static void printBstr( const char *S, const uint8_t *key, size_t L) {
    size_t i;
    printf( "%s", S);
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
