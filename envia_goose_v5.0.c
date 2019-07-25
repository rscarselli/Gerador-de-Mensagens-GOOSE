/* Para rodar manualmente no linux, use:
 * sudo gcc gcry.c envia_goose.c aes.c sha256.c cmac.c -lgcrypt -lgpg-error -o envia_goose
 * sudo ./envia_goose 1 0
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

#define DEFAULT_IF      "enxb827ebe9a3f0"
//#define DEFAULT_IF      "wlan0"
#define TAMANHO_BUF     512

#define IPAD 0x36 //definido na RFC2104
#define OPAD 0x5c //definido na RFC2104
#define SHA256_BLOCK 64 //tamanho do bloco interno do algoritmo, 512 bits

int criaPacoteCompleto(char *buffer, uint16_t AppID, char *gocbRef, char *datSet, char *goID, uint8_t stNum, uint8_t sqNum);
int criaPacote(char *buffer);
void imprimeHex(char *msg, int tamanho);
void imprimePacote(char *msg, int tamanho);
void enviaPacote(char *mensagem, int tamanho);//retorna o sockfd
int adicionaNoPacote(char *pacote, char *conteudo, int tamanho_pacote, int tamanho_conteudo);
char *geraHash(char *pacote, int tamanho);
char *geraCifraAES(char *texto, char *chave, int tamanho);
char *geraCifraRSA(char *texto, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho);
char *geraHMAC(char *msg, int tamanho, char *chave, int tamanho_chave);

int main(int argc, char *argv[]){
    struct timeval tempo1, tempo2;
    struct timeval total1, total2;

    printf("\n#  ##### Programa Envia Pkt Goose #####  #\n");
    int qtd_pacotes = 1;
    int tipo_seguranca = 0;
    int conteudo_extra = 0;
    if(argc > 1) sscanf(argv[1], "%d", &qtd_pacotes);
    if(argc > 2) sscanf(argv[2], "%d", &tipo_seguranca);
    if(argc > 3) sscanf(argv[3], "%d", &conteudo_extra);
    printf("Quantidade a ser enviada: %d\n", qtd_pacotes);
    if(tipo_seguranca==0) printf("Tipo de Segurança: NENHUMA\n");
    if(tipo_seguranca==1) printf("Tipo de Segurança: HASH\n");
    if(tipo_seguranca==2) printf("Tipo de Segurança: CRIPTOGRAFIA SIMÉTRICA AES256\n");
    if(tipo_seguranca==3) printf("Tipo de Segurança: CRIPTOGRAFIA ASSIMÉTRICA RSA\n");
    if(tipo_seguranca==4) printf("Tipo de Segurança: HMAC (Hash-based Message Authentication Code)\n");
    if(tipo_seguranca==5) printf("Tipo de Segurança: CMAC (Cypher-based Message Authentication Code)\n");
    if(tipo_seguranca<0 || tipo_seguranca>5) return 0;

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

    char buffer[TAMANHO_BUF];//alocacao de memoria para montar o pacote em HEX
    int t_buffer = 0;//tamanho do pacote atual
    uint8_t *chave = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

    //codigo para preparacao do RSA
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
    //fim do codigo para preparacao do RSA
    //codigo para preparacao do CMAC
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, chave);
    unsigned char L[16], K1[16], K2[16];
    if(tipo_seguranca==5){
        for ( int i=0; i<16; i++ ) L[i] = 0x00;
        AES_ECB_encrypt(&ctx, L);//prepara chave CMAC
        generate_subkey(chave,K1,K2);
    }
    //fim do codigo para preparacao do CMAC
    //montagem e envio do pacote
    gettimeofday(&total1, NULL);
    for(int i=0; i<qtd_pacotes;i++){
        if(i == 0) gettimeofday(&tempo1, NULL);
        t_buffer = criaPacote(buffer);
        if(tipo_seguranca==1) t_buffer = adicionaNoPacote(buffer, geraHash(buffer, t_buffer), t_buffer, SHA256_BLOCK_SIZE); //adiciona 32 bytes do digest SHA256 no pacote
        if(tipo_seguranca==2) t_buffer = adicionaNoPacote(buffer, geraCifraAES(geraHash(buffer, t_buffer), chave, SHA256_BLOCK_SIZE), t_buffer, SHA256_BLOCK_SIZE);
        if(tipo_seguranca==3) t_buffer = adicionaNoPacote(buffer, geraCifraRSA(geraHash(buffer, t_buffer), pubk, privk, SHA256_BLOCK_SIZE), t_buffer, 32);
        if(tipo_seguranca==4) t_buffer = adicionaNoPacote(buffer, geraHMAC(buffer, t_buffer, chave, 16), t_buffer, SHA256_BLOCK_SIZE);
        if(tipo_seguranca==5){
            unsigned char cmac[16];
            AES_CMAC(L, buffer, t_buffer, cmac);
            t_buffer = adicionaNoPacote(buffer, cmac, t_buffer, AES_BLOCKLEN);
        }
        if(conteudo_extra > 0){
            if(conteudo_extra > 400) conteudo_extra = 400;
            char preenchimento[conteudo_extra];
            for(int i=0; i<conteudo_extra; i++) preenchimento[i] = 0xCA;
            t_buffer = adicionaNoPacote(buffer, preenchimento, t_buffer, conteudo_extra);
        }
        if(sendto(sockfd, buffer, t_buffer, 0,
            (struct sockaddr*)&socket_address,
                sizeof(struct sockaddr_ll)) < 0)
                    printf("Falha no envio\n");
        //enviaPacote(buffer, t_buffer);
        if(i == 9) gettimeofday(&tempo2, NULL);

    }
    gettimeofday(&total2, NULL);
    printf("Mensagem enviada com sucesso ! \n\n");
    if(qtd_pacotes >= 10) printf("Tempo de PROCESSAMENTO MEDIO dos 10 primeiros pacotes  = %ld microssegundos\n",
                (((tempo2.tv_sec - tempo1.tv_sec) * 1000000) + (tempo2.tv_usec - tempo1.tv_usec))/10);
    printf("Tempo de PROCESSAMENTO MEDIO de TODOS os [%d] pacotes  = %ld microssegundos\n", qtd_pacotes,
                (((total2.tv_sec-total1.tv_sec) * 1000000) + (total2.tv_usec-total1.tv_usec))/qtd_pacotes);
    //printf("\n");
    printf("Tamanho do pacote final: %d\n\n",t_buffer);
    if(tipo_seguranca==3){
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
    /* Address length *
    socket_address.sll_halen = ETH_ALEN;

    /* ENVIO DO PACOTE */
    if(sendto(sockfd, mensagem, tamanho, 0,
        (struct sockaddr*)&socket_address,
            sizeof(struct sockaddr_ll)) < 0)
                printf("Falha no envio\n");
    //close(sockfd);
    //return sockfd;
}//*/

int adicionaNoPacote(char *pacote, char *conteudo, int tamanho_pacote, int tamanho_conteudo){
    for(int i=0;i<tamanho_conteudo;i++) pacote[tamanho_pacote+i] = conteudo[i];

	return tamanho_pacote + tamanho_conteudo;
}

char *geraHash(char *texto, int tamanho){
    char *buf = malloc(SHA256_BLOCK_SIZE);
    SHA256_CTX ctx;

    sha256_init(&ctx);
	sha256_update(&ctx, texto, tamanho);
	sha256_final(&ctx, buf);

	return buf;
}

char *geraCifraAES(char *texto, char *chave, int tamanho){
    uint8_t *buf = malloc(tamanho);
	for(int i=0;i<tamanho;i++) buf[i] = texto[i];
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, chave);
    AES_ECB_encrypt(&ctx, buf);

	return buf;
}

char *geraCifraRSA(char *texto, gcry_sexp_t pub_key, gcry_sexp_t priv_key, int tamanho){
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

// HMAC = H(K XOR opad, H(K XOR ipad, text))
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

