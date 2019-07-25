/* Para rodar manualmente no linux, use:
 * sudo gcc envia_goose_cifra_tudo_v1.1.c aes.c sha256.c gcry.c -lgcrypt -lgpg-error -o cifrar_pacote_completo
 * sudo ./cifrar_pacote_completo
 * parâmetro 1 significa quantidade de pacotes, deve ser inteiro positivo
 * parâmetro 2 significa modo de seguranca, varia de 1 a 2
 * deve ser alterado o limite do S.O. de arquivos abertos com o comando:
 * ulimit -aS | grep open
 * ulimit -n 10100
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
#include "gcry.h"           //para cadastrar rsa

#define DESTINO_MAC0    0x01
#define DESTINO_MAC1    0x0c
#define DESTINO_MAC2    0xcd
#define DESTINO_MAC3    0x01
#define DESTINO_MAC4    0x00
#define DESTINO_MAC5    0x01

#define DEFAULT_IF      "enxb827ebe9a3f0"
//#define DEFAULT_IF      "wlan0"
#define TAMANHO_BUF     512

#define SHA256_BLOCK 64 //tamanho do bloco interno do algoritmo, 512 bits

int criaPacoteCompleto(char *buffer, uint16_t AppID, char *gocbRef, char *datSet, char *goID, uint8_t stNum, uint8_t sqNum);
int criaPacote(char *buffer);
void imprimeHex(char *msg, int tamanho);
void imprimePacote(char *msg, int tamanho);
void enviaPacote(char *mensagem, int tamanho);
int adicionaNoPacote(char *pacote, char *conteudo, int tamanho_pacote, int tamanho_conteudo);
void *geraHash(char *resposta, char *pacote, int tamanho);
void *geraCifraAES(char *resposta, char *texto, char *chave, int tamanho);
char *geraCifraRSA(char *texto, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho);

int main(int argc, char *argv[]){
    struct timeval total1, total2;

    printf("\n#  ##### Programa Envia Pkt Goose #####  #\n");
    int qtd_pacotes = 1;
    int tipo_seguranca = 1;
    if(argc > 1) sscanf(argv[1], "%d", &qtd_pacotes);
    if(argc > 2) sscanf(argv[2], "%d", &tipo_seguranca);

    char buffer[TAMANHO_BUF];//alocacao de memoria para montar o pacote em HEX
    int t_buffer = 0;//tamanho do pacote atual
    uint8_t *chave = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

    //inicio do codigo de envio*********************
    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    struct sockaddr_ll socket_address;

    /* Get interface name */
    char ifName[IFNAMSIZ];
    strcpy(ifName, DEFAULT_IF);

    /* Abrir RAW socket para enviar */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("socket");
        exit(1);
    }
    /* Captura o indice da interface para enviar */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    /* Captura o endereço MAC da interface para enviar */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length */
    socket_address.sll_halen = ETH_ALEN;
    //fim do codigo de envio************************

    //apenas para RSA
    gcrypt_init();
    gcry_error_t err;
    gcry_sexp_t pubk, privk;

    //preparacao do algoritmo de criptografia
    switch(tipo_seguranca){
        case 1:
        printf("Selecionado: AES 128 bits para [%d] pacotes.\n", qtd_pacotes);


        break;

        case 2:
        printf("Selecionado: RSA 2048 bits para [%d] pacotes.\n", qtd_pacotes);

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

        break;

        default:
        printf("Valor invalido!\n");
    }

    //montagem e envio do pacote
    char *cifra_do_payload = malloc(TAMANHO_BUF);
    char buffer_payload[TAMANHO_BUF];

    gettimeofday(&total1, NULL);
    for(int i=0; i<qtd_pacotes;i++){
        t_buffer = criaPacote(buffer);
        for(int i=0; i<t_buffer; i++) if(i>13) buffer_payload[i-14] = buffer[i];

        if(tipo_seguranca==1) geraCifraAES(cifra_do_payload, buffer_payload, chave, t_buffer);
        if(tipo_seguranca==2) cifra_do_payload = geraCifraRSA(buffer_payload, pubk, privk, t_buffer);

        if(adicionaNoPacote(buffer, cifra_do_payload, 14, t_buffer-14)!=t_buffer) printf("Falha na cifra do payload.\n");

        if(sendto(sockfd, buffer, t_buffer, 0,
            (struct sockaddr*)&socket_address,
                sizeof(struct sockaddr_ll)) < 0)
                    printf("Falha no envio\n");
    }
    gettimeofday(&total2, NULL);
    long int t_total = (((total2.tv_sec-total1.tv_sec) * 1000000) + (total2.tv_usec-total1.tv_usec))/qtd_pacotes;
    printf("Tempo de PROCESSAMENTO MEDIO de cada um dos [%d] pacotes  = %ld microssegundos\n", qtd_pacotes, t_total);

    if(tipo_seguranca==2){
        gcry_sexp_release(pubk);
        gcry_sexp_release(privk);

    }
    return 0;
}

int criaPacote(char *buffer){
    uint16_t AppID = 65535;
    unsigned char *gocbRef = "teste IED Rafael";
    unsigned char *datSet = "Device900/GOOSE1";
    unsigned char *goID = "900_GOOSE1";
    uint8_t stNum = 0x01;
    uint8_t sqNum = 0x01;

    return criaPacoteCompleto(buffer, (uint16_t)AppID, gocbRef, datSet, goID, stNum, sqNum);
}

int criaPacoteCompleto(char *buffer, uint16_t AppID, char *gocbRef, char *datSet, char *goID, uint8_t stNum, uint8_t sqNum){
    int fd;
    int tx_len = 0;
    struct ifreq origem;
    struct timeval agora;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    origem.ifr_addr.sa_family = AF_INET;

    //strncpy(origem.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
    strcpy(origem.ifr_name, DEFAULT_IF);
    ioctl(fd, SIOCGIFHWADDR, &origem);
    close(fd);

    unsigned char *mac = (unsigned char *) origem.ifr_hwaddr.sa_data;
    //printf("MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    buffer[0] = DESTINO_MAC0;
    buffer[1] = DESTINO_MAC1;
    buffer[2] = DESTINO_MAC2;
    buffer[3] = DESTINO_MAC3;
    buffer[4] = DESTINO_MAC4;
    buffer[5] = DESTINO_MAC5;
    for(int i=6;i<12;i++) buffer[i] = mac[i-6];
    tx_len += 12;
    //ate aqui inseriu os 2 macs
    buffer[tx_len++] = 0x88; //ETH TYPE
    buffer[tx_len++] = 0xB8; //ETH TYPE

    //aqui comeca o cabecalho goose
    buffer[tx_len++] = 0xff; //GOOSE APPID
    buffer[tx_len++] = 0xff; //GOOSE APPID
    uint16_t goose_length = 00; //GOOSE LENGTH
    int local_goose_length = tx_len;
    buffer[tx_len++] = goose_length>>8;
    buffer[tx_len++] = goose_length;
    for(int i=0;i<4;i++) buffer[tx_len++] = 0x00;//reserved 1 e 2
    //aqui termina o cabecalho goose

    //aqui comeca o goose APDU
    //goosePDU TAG
    buffer[tx_len++] = 0x61;//x61
    //goosePDU LENGTH
    int local_goosePDU_length = tx_len;
    buffer[tx_len++] = (uint8_t) 0;
    //goosePDU DATA

    buffer[tx_len++] = 0x80;                                            //gocbRef TAG
    buffer[tx_len++] = (uint8_t) strlen(gocbRef);                       //gocbRef Length
    for(int i=0;i<strlen(gocbRef);i++) buffer[tx_len++] = gocbRef[i];   //gocbRef Data
    buffer[local_goosePDU_length] += 2 + strlen(gocbRef);               //atualiza size APDU

    buffer[tx_len++] = 0x81;                                            //timeAllowedtoLive TAG
    buffer[tx_len++] = (uint8_t) 2;                                     //timeAllowedtoLive Length
    uint16_t goose_ttl = 4000;                                          //timeAllowedtoLive Data
    buffer[tx_len++] = goose_ttl>>8;                                    //timeAllowedtoLive
    buffer[tx_len++] = goose_ttl;                                       //timeAllowedtoLive
    buffer[local_goosePDU_length] += 2 + sizeof(goose_ttl);             //atualiza size APDU

    buffer[tx_len++] = 0x82;                                            //datSet TAG
    buffer[tx_len++] = (uint8_t) strlen(datSet);                        //datSet Length
    for(int i=0;i<strlen(datSet);i++) buffer[tx_len++] = datSet[i];     //datSet Data
    buffer[local_goosePDU_length] += 2 + strlen(datSet);                //atualiza size APDU

    buffer[tx_len++] = 0x83;                                            //goID TAG
    buffer[tx_len++] = (uint8_t) strlen(goID);                          //goID Length
    for(int i=0;i<strlen(goID);i++) buffer[tx_len++] = goID[i];         //goID Data
    buffer[local_goosePDU_length] += 2 + strlen(goID);                  //atualiza size APDU

    buffer[tx_len++] = 0x84;                                            //time TAG
    buffer[tx_len++] = (uint8_t) sizeof(agora);                         //time Length
    gettimeofday(&agora, NULL);                                         //time
    int segundos = agora.tv_sec-10800;//menos 3 horas, horario BSB      //time
    int usegundos= agora.tv_usec;                                       //time
    for(int i=4; i>0; i--) buffer[tx_len++] = segundos>>8*(i-1);        //4 bytes
    for(int i=3; i>0; i--) buffer[tx_len++] = usegundos>>8*(i-1);       //3 bytes
    buffer[tx_len++] = 0x00; //time quality flag, 1 byte                //time
    buffer[local_goosePDU_length] += 2 + sizeof(agora);                 //atualiza size APDU

    buffer[tx_len++] = 0x85;                                            //stNum TAG
    buffer[tx_len++] = stNum;                                           //stNum Length
    buffer[tx_len++] = sizeof(stNum);                                   //stNum Data
    buffer[local_goosePDU_length] += 2 + sizeof(stNum);                 //atualiza size APDU

    buffer[tx_len++] = 0x86;                                            //sqNum TAG
    buffer[tx_len++] = sqNum;                                           //sqNum Length
    buffer[tx_len++] = sizeof(sqNum);                                   //sqNum Data
    buffer[local_goosePDU_length] += 2 + sizeof(sqNum);                 //atualiza size APDU

    buffer[tx_len++] = 0x87;                                           //test TAG
    buffer[tx_len++] = (uint8_t) 1;                                    //test Length
    buffer[tx_len++] = 0x01;                                           //test Data
    buffer[local_goosePDU_length] += 3;                                 //atualiza size APDU

    buffer[tx_len++] = 0x88;                                           //confRev TAG
    buffer[tx_len++] = (uint8_t) 1;                                    //confRev Length
    buffer[tx_len++] = 0x01;                                           //confRev Data
    buffer[local_goosePDU_length] += 3;                                 //atualiza size APDU

    buffer[tx_len++] = 0x89;                                           //ndsCom TAG
    buffer[tx_len++] = (uint8_t) 1;                                    //ndsCom Length
    buffer[tx_len++] = 0x00;                                           //ndsCom Data
    buffer[local_goosePDU_length] += 3;                                 //atualiza size APDU

    buffer[tx_len++] = 0x8A;                                           //numDatSetEntries TAG
    buffer[tx_len++] = (uint8_t) 1;                                    //numDatSetEntries Length
    buffer[tx_len++] = 0x01;                                           //numDatSetEntries Data
    buffer[local_goosePDU_length] += 3;                                 //atualiza size APDU

    buffer[tx_len++] = 0xAB;                                           //allData TAG
    buffer[tx_len++] = (uint8_t) 3;                                    //allData Length
    buffer[tx_len++] = 0x83;                                           //boolean TAG
    buffer[tx_len++] = 0x01;                                           //boolean Length
    buffer[tx_len++] = 0x00;                                           //boolean Data
    buffer[local_goosePDU_length] += 5;                                 //atualiza size APDU


    //aqui termina o goose APDU

    int tamanho_final = 10 + buffer[local_goosePDU_length];//atualiza size goose cabecalho
    buffer[local_goose_length] = tamanho_final>>8;      //GOOSE LENGTH
    buffer[local_goose_length+1] = tamanho_final;       //GOOSE LENGTH
    return tx_len;
}

void imprimeHex(char *msg, int tamanho){
    if(tamanho == 0) return;
    if(tamanho--%4==0)printf(" ");
    printf("%02hhX", *msg);
    imprimeHex(++msg, tamanho);
    if(tamanho == 0) printf("\n");
}

void imprimePacote(char *msg, int tamanho){
    printf("\nMAC de Destino: ");
    for(int i=0;i<6;i++){
        printf("%02hhX", msg[i]);
        if(i<5) printf(":");
    }
    printf("\nMAC de Origem: ");
    for(int i=6;i<12;i++){
        printf("%02hhX", msg[i]);
        if(i<11) printf(":");
    }
    printf("\nEther Type: ");
    if(msg[12]==0x88 && msg[13]==0xb8){
        printf("Goose");
        printf("\nGoose Length: %d", msg[17]);
    }
    else printf("Outro");
}

void enviaPacote(char *mensagem, int tamanho){
    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    struct sockaddr_ll socket_address;

    /* Get interface name */
    char ifName[IFNAMSIZ];
    strcpy(ifName, DEFAULT_IF);

    /* Abrir RAW socket para enviar */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("socket");
    }
    /* Captura o indice da interface para enviar */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    /* Captura o endereço MAC da interface para enviar */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length */
    socket_address.sll_halen = ETH_ALEN;

    /* ENVIO DO PACOTE */
    if(sendto(sockfd, mensagem, tamanho, 0,
        (struct sockaddr*)&socket_address,
            sizeof(struct sockaddr_ll)) < 0)
                printf("Falha no envio\n");
}

int adicionaNoPacote(char *pacote, char *conteudo, int tamanho_pacote, int tamanho_conteudo){
    for(int i=0;i<tamanho_conteudo;i++) pacote[tamanho_pacote+i] = conteudo[i];

	return tamanho_pacote + tamanho_conteudo;
}

void *geraHash(char *resposta, char *texto, int tamanho){
    SHA256_CTX ctx;

    sha256_init(&ctx);
	sha256_update(&ctx, texto, tamanho);
	sha256_final(&ctx, resposta);
}

void *geraCifraAES(char *resposta, char *texto, char *chave, int tamanho){
    //uint8_t *buf[tamanho];
	for(int i=0;i<tamanho;i++) resposta[i] = texto[i];
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, chave);
    AES_ECB_encrypt(&ctx, resposta);
}

char *geraCifraRSA(char *texto, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho){
    gcry_error_t err;

    /* Create a message. */
    gcry_mpi_t msg;
    gcry_sexp_t data;
    const unsigned char* s = (const unsigned char*) texto;
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, (const unsigned char*) texto, tamanho, NULL);
    if (err) xerr("failed to create a mpi from the message");

    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", msg);
    if (err) xerr("failed to create a sexp from the message");

    /* Encrypt the message. */
    gcry_sexp_t ciph;
    err = gcry_pk_encrypt(&ciph, data, pub_key);
    if (err) xerr("gcrypt: encryption failed");
    //limpeza
    gcry_mpi_release(msg);
    gcry_sexp_release(data);

    return gcry_sexp_nth_string(ciph, 0);
}

