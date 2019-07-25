/* Para rodar manualmente no linux, use:
 * sudo gcc gcry.c recebe_goose.c aes.c sha256.c cmac.c -lgcrypt -lgpg-error -o recebe_goose
 * sudo ./recebe_goose 1 0
 * parâmetro 1 significa quantidade de pacotes, deve ser inteiro positivo
 * parâmetro 2 significa modo de seguranca, varia de 0 a 4
 */

#include <stdio.h>          //printf
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>         //strncpy
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>         //ifreq
#include <unistd.h>         //close
#include <netinet/ether.h>
#include <sys/time.h>       //gettimeofday
#include "sha256.h"
#include "aes.h"
#include "cmac.h"
#include "gcry.h"           //para cadastrar rsa

#define DESTINO_MAC0    0x01
#define DESTINO_MAC1    0x0c
#define DESTINO_MAC2    0xcd
#define DESTINO_MAC3    0x01
#define DESTINO_MAC4    0x00
#define DESTINO_MAC5    0x01

//#define ETHER_TYPE	0x0001 //ETH_P_802_3
#define ETHER_TYPE	0x0003 //ETH_P_ALL
//#define ETHER_TYPE	0x8100 //ETH_P_8021Q
//#define ETHER_TYPE	0x0800 //ETH_P_IP

#define DEFAULT_IF      "enxb827ebe9a3f0"
//#define DEFAULT_IF      "wlan0"
#define TAMANHO_BUF     256

#define IPAD 0x36 //definido na RFC2104
#define OPAD 0x5c //definido na RFC2104
#define SHA256_BLOCK 64 //tamanho do bloco interno do algoritmo, 512 bits

void imprimeHex(char *msg, int tamanho);
char *geraHash(char *texto, int tamanho);
char *geraDecifraAES(char *texto, char *chave, int tamanho);
char *geraDecifraRSA(char *cifra, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho);
char *geraHMAC(char *msg, int tamanho, char *chave, int tamanho_chave);

int main(int argc, char *argv[])
{
	struct timeval t1, t2;
    struct timeval total1, total2;

	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buffer[TAMANHO_BUF];
	char ifName[IFNAMSIZ];

	strcpy(ifName, DEFAULT_IF);
	uint8_t *chave = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

	printf("\n#  ##### Programa Recebe Pkt Goose #####  #\n");
	int qtd_pacotes = 1;
    int tipo_seguranca = 0;
    int conteudo_extra = 0;
    if(argc > 1) sscanf(argv[1], "%d", &qtd_pacotes);
    if(argc > 2) sscanf(argv[2], "%d", &tipo_seguranca);
    printf("Quantidade a ser enviada: %d\n", qtd_pacotes);
    /*int qtd_pacotes = -1;
    int tipo_seguranca = -1;
    while(qtd_pacotes < 1){
        printf("Digite a quantidade de pacotes a ser recebida: ");
        scanf("%d", &qtd_pacotes);
    }
    while(tipo_seguranca < 0){
        printf("\nDigite o tipo de segurança dos pacotes recebidos: ");
        printf("\n          Digite 0 para segurança: NENHUMA");
        printf("\n          Digite 1 para segurança: HASH sha256 do pacote");
        printf("\n          Digite 2 para segurança: CIFRA aes128 de um hash do pacote");
        printf("\n          Digite 3 para segurança: CIFRA rsa2048");
        printf("\n          Digite 4 para segurança: HMAC (Hash-based Message Authentication Code)");
        printf("\n          Digite 5 para segurança: CMAC (Cypher-based Message Authentication Code)\n");
        scanf("%d", &tipo_seguranca);
    }*/

    if(tipo_seguranca==0) printf("Tipo de Segurança: NENHUMA\n");
    if(tipo_seguranca==1) printf("Tipo de Segurança: HASH SHA256\n");
    if(tipo_seguranca==2) printf("Tipo de Segurança: CRIPTOGRAFIA SIMÉTRICA AES128\n");
    if(tipo_seguranca==3) printf("Tipo de Segurança: CRIPTOGRAFIA ASSIMÉTRICA RSA2048\n");
    if(tipo_seguranca==4) printf("Tipo de Segurança: HMAC (Hash-based Message Authentication Code)\n");
    if(tipo_seguranca==5) printf("Tipo de Segurança: CMAC (Cypher-based Message Authentication Code)\n");
    if(tipo_seguranca<0 || tipo_seguranca>5) return 0;

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buffer;
	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
    //codigos para RSA
    gcrypt_init();
    gcry_error_t err;
    gcry_sexp_t pubk, privk;
    if(tipo_seguranca==3){
        FILE* lockf = fopen("rsa-key.sp", "rb");
        if (!lockf) xerr("fopen() falhou");
        /* Grab a key pair password and create an AES context with it. */
        gcry_cipher_hd_t aes_hd;
        get_aes_ctx(&aes_hd);
        /* Read and decrypt the key pair from disk. */
        size_t rsa_len = get_keypair_size(2048);
        char* rsa_buf = calloc(1, rsa_len);
        if (!rsa_buf) xerr("malloc: buffer RSA nao pode ser alocado.");

        if (fread(rsa_buf, rsa_len, 1, lockf) != 1) xerr("fread() falhou");

        err = gcry_cipher_decrypt(aes_hd, (unsigned char*) rsa_buf, rsa_len, NULL, 0);
        if (err) xerr("gcrypt: falha na decriptografia do par de chaves.");
        /* Load the key pair components into sexps. */
        gcry_sexp_t rsa_keypair;
        err = gcry_sexp_new(&rsa_keypair, rsa_buf, rsa_len, 0);
        pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
        privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
        //printf("%d\n",gcry_sexp_length(rsa_keypair));

        gcry_sexp_release(rsa_keypair);
        gcry_cipher_close(aes_hd);
        free(rsa_buf);
        fclose(lockf);
    }
    //fim dos codigos para RSA
    //inicio codigos CMAC
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, chave);
    unsigned char L[16], K1[16], K2[16], cmac[16];
    if(tipo_seguranca==5){
        for ( int i=0; i<16; i++ ) L[i] = 0x00;
        AES_ECB_encrypt(&ctx, L);//prepara chave CMAC
        generate_subkey(chave,K1,K2);
    }
    //fim codigos CMAC
	printf("Recebedor de pacotes ativo, recebendo pacotes.\n");
    int tam_seguranca = 0;
    if(tipo_seguranca>0 && tipo_seguranca<5) tam_seguranca = 32;
    else if(tipo_seguranca==5) tam_seguranca = 16;
    int count = 0, x=0, y=0;
    while(count < qtd_pacotes){
        numbytes = recvfrom(sockfd, buffer, TAMANHO_BUF, 0, NULL, NULL);
        x++;
        if (buffer[12] == 0x88 && buffer[13] == 0xb8) {
            //printf("Mensagem Goose Recebida!\n");
            y++;
            if(count==0) gettimeofday(&total1, NULL);
            //calcular a segurança do GOOSE
            uint8_t payload[numbytes-tam_seguranca];
            for(int i=0; i<numbytes-tam_seguranca; i++) payload[i] = buffer[i];
            uint8_t rabicho[tam_seguranca];
            for(int i=0; i<tam_seguranca; i++) rabicho[i] = buffer[(numbytes-tam_seguranca)+i];

            switch(tipo_seguranca){
                case 0:
                //sem segurança não faz nada no pacote
                    //printf("Pacote sem segurança recebido.\n");
                break;
                case 1:
                    if(strncmp(geraHash(payload, sizeof(payload)), rabicho, 32) != 0){
                        printf("Hash incorreto.\n");
                        return 0;
                    }
                break;
                case 2:
                    if(strncmp(geraHash(payload, sizeof(payload)), geraDecifraAES(rabicho, chave, 32), 32) != 0){
                        printf("Cifra AES incorreta.\n");
                        return 0;
                    }
                break;
                case 3:
                    if(strncmp(geraDecifraRSA(geraHash(payload, sizeof(payload)), pubk, privk, 32), rabicho, 32) != 0){
                        //printf("Cifra RSA incorreta.\n");
                        //return 0;
                    }
                break;
                case 4:
                    if(strncmp(geraHMAC(payload, sizeof(payload), chave, 16), rabicho, 32) != 0){
                        printf("HMAC incorreto.\n");
                        return 0;
                    }
                break;
                case 5:
                    AES_CMAC(L, payload, sizeof(payload), cmac);
                    if(strncmp(cmac, rabicho, 16) != 0){
                        imprimeHex(buffer, numbytes);
                        printf("\n\n");
                        imprimeHex(rabicho, tam_seguranca);
                        printf("CMAC incorreto.\n");
                        return 0;
                    }
                break;
                default:
                    printf("Valor invalido!\n");
            }
            count++;
        }
    }
    gettimeofday(&total2, NULL);

    long int resultado = (((total2.tv_sec-total1.tv_sec) * 1000000) + (total2.tv_usec-total1.tv_usec))/qtd_pacotes;
    printf("Tempo de RECEBIMENTO MEDIO = %ld microssegundos\n",resultado);
    printf("Qtd de pacotes recebidos: %d\n", x);
    printf("Qtd de pacotes GOOSE recebidos: %d\n", y);
    printf("\n====================  FIM!  ====================\n\n");

	close(sockfd);
	return ret;
}

void imprimeHex(char *msg, int tamanho){
    if(tamanho == 0) return;
    if(tamanho--%4==0)printf(" ");
    printf("%02hhX", *msg);
    imprimeHex(++msg, tamanho);
    if(tamanho == 0) printf("\n");
}

char *geraHash(char *texto, int tamanho){
    char *buf = malloc(SHA256_BLOCK_SIZE);
    SHA256_CTX ctx;

    sha256_init(&ctx);
	sha256_update(&ctx, texto, tamanho);
	sha256_final(&ctx, buf);

	return buf;
}

char *geraDecifraAES(char *texto, char *chave, int tamanho){
    uint8_t *buf = malloc(tamanho);
	for(int i=0;i<tamanho;i++) buf[i] = texto[i];
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, chave);
    AES_ECB_decrypt(&ctx, buf);

	return buf;
}

char *geraDecifraRSA(char *texto, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho){
    gcry_error_t err;

    /* Create a message. */
    gcry_mpi_t msg;
    gcry_sexp_t data;
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, (const unsigned char*) texto, tamanho, NULL);
    if (err) xerr("failed to create a mpi from the message");

    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %M))", msg);
    if (err) xerr("failed to create a sexp from the message");

    /* Encrypt the message. */
    gcry_sexp_t ciph;
    err = gcry_pk_encrypt(&ciph, data, pub_key);
    if (err) xerr("gcrypt: encryption failed");
    //limpeza
    gcry_mpi_release(msg);
    gcry_sexp_release(data);

    gcry_mpi_t saida = gcry_sexp_nth_mpi(ciph, 0, GCRYMPI_FMT_USG);
    char *resposta = malloc(64);
    for(int i=0; i<32; i++) resposta[i] == 0;
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) resposta, 32, NULL, saida);
    if (err) xerr("falha ao criar string mpi\n");

    return resposta;
}

char *geraHMAC(char *msg, int tamanho, char *chave, int tamanho_chave){
    char *hmac = malloc(SHA256_BLOCK_SIZE);
    char k[SHA256_BLOCK] = {0};
    SHA256_CTX ctx;

    if(tamanho_chave > SHA256_BLOCK){//chave maior q tamanho do bloco SHA256, gera hash da chave
        sha256_init(&ctx);
        sha256_update(&ctx, chave, tamanho_chave);
        sha256_final(&ctx, k);
    }
    else if(tamanho_chave < SHA256_BLOCK){//chave menor q tamanho do bloco SHA256, preenche restante com 0x00
        int i;
        for(i=0; i<SHA256_BLOCK; i++){
            if(i<tamanho_chave){
                k[i] = chave[i];
            }else{
                k[i] = 0x00;
            }
        }
    }
    else if(tamanho_chave = SHA256_BLOCK){//chave com mesmo tamanho que bloco SHA256, mantem a chave
        for(int i=0; i<SHA256_BLOCK; i++){
            k[i] = chave[i];
        }
    }

    char k_xor_ipad[SHA256_BLOCK] = {0};
    char k_xor_opad[SHA256_BLOCK] = {0};

    for(int i=0; i<SHA256_BLOCK; i++){
        k_xor_ipad[i] = k[i] ^ IPAD; //inner pad, conforme rfc
        k_xor_opad[i] = k[i] ^ OPAD; //outer pad, conforme rfc
    }

    //hash da etapa 1
    char inner_concat_msg[SHA256_BLOCK+tamanho];//para concatenar ipad + msg
    char hash_ipad_msg[SHA256_BLOCK_SIZE] = {0};//para guardar o hash da primeira etapa

    for(int i=0; i<SHA256_BLOCK+tamanho; i++){//preenche a concatenação com ipad+msg
        if(i<SHA256_BLOCK) inner_concat_msg[i] = k_xor_ipad[i];
        else inner_concat_msg[i] = msg[i-SHA256_BLOCK];
    }
    sha256_init(&ctx);//inner hash
    sha256_update(&ctx, inner_concat_msg, SHA256_BLOCK+tamanho);
    sha256_final(&ctx, hash_ipad_msg);

    //hash da etapa 2, resultado é o HMAC
    char outer_concat_msg[SHA256_BLOCK+SHA256_BLOCK_SIZE];//para concatenar opad + inner_hash, 64+32

    for(int i=0; i<SHA256_BLOCK+SHA256_BLOCK_SIZE; i++){//preenche a concatenação com opad+inner_hash
        if(i<SHA256_BLOCK) outer_concat_msg[i] = k_xor_opad[i];
        else outer_concat_msg[i] = hash_ipad_msg[i-SHA256_BLOCK];
    }
    sha256_init(&ctx);//outer hash
    sha256_update(&ctx, outer_concat_msg, SHA256_BLOCK+SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hmac);

	return hmac;
}
