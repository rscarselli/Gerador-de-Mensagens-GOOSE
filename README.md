# Envio_GOOSE
Envio de mensagens GOOSE criptografadas

Existem três programas básicos que fazem parte desse conjunto de códigos. O primeiro deles é o envia_goose. É um programa que recebe 2 parâmetros de entrada, sendo o primeiro deles a quantidade de pacotes a ser enviada e o segundo é o modo de segurança que varia de 0 a 4.
O programa gera mensagens GOOSE diferentes entre si apenas no atribudo GoosePDU.t, processa o modo de segurança e envia a mensagem via interface de rede. Para isso deve ser ajustado a constante DEFAULT_IF no inicio do código para o nome da interface de rede do host que está executando o código.

Os algoritmos de criptografia SHA256, AES128, HMAC_SHA256 e CMAC_AES128 são implementações próprias, também anexas a este projeto. Somente o algoritmo RSA2048 está configurado para utilizar a biblioteca Libgcrypt do GNUPG. Os códigos estão bem comentados para melhor detalhamento das funções, ao final o programa calcula o tempo médio de envio das mensagens GOOSE. Para envio das mensagens, o pacote gerado possui 109 bytes mais o adicional de segurança caso exista. O gerador de pacotes está na função criaPacoteCompleto.

Existem algumas funções auxiliares para throubleshooting, como a imprimeHex e a imprimePacote, além de alguns prints estratégicos comentados no código.

O segundo programa é o recebe_goose, que possui os mesmos parâmetros de entrada do envio. Esse algoritmo processa o recebimento de mensagens GOOSE enviadas via multicast na rede. Ao receber a mensagem, ele valida ela através do calculo de segurança conforme o algoritmo selecionado no parâmetro de entrada. Em caso de mensagem GOOSE recebida de forma incorreta, ele imprime mensagens de erro. Ao final o programa imprime o tempo médio de recebimento de cada mensagem em microssegundos.

O terceiro programa é o cifra_tudo. Este programa possui os mesmos parâmetros de entrada dos dois primeiros, porém aqui o segundo parâmetro só aceita as entradas '1' e '2', pois ele só criptografa com duas opções de algoritmos: AES128 ou RSA2048. Diferente dos outros programas que adicional bytes de segurança ao final da mensagem, este aqui criptografa todo o payload da mensagem, só deixa descriptografado o cabeçalho ethernet. Ao final da execução, o programa imprime o tempo médio de processamento de cada mensagem em microssegundos.
