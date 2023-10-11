#include <stdio.h>
#include <stdint.h>

/**
Variaveis globais;

Tabelas fixas para o algoritimo de criptografia DES
E variaveis auxiliares para as fun��es

nota; toda vez que aparecer unit8_t � um inteiro n�o assinado de 8 bits, literalmente um char, unsigned, mas fica mais facil para ler.
**/

int IP[] ={
    //Initial Permutation, permuta��o aplicada no texto em binario.
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

int PC1[] ={
    //Permutation choice 1, primeira permuta��o aplicada a key de 64 bits, e apos a permuta��o retorna uma key de 56 bits
    57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

int SHIFTS[] ={
    //Bit Shifts a esquerda de maneira circular aplicadas 16 vezes a uma chave para criar 16 chaves de 56 bits
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

int PC2[] ={
    //Permutation choice 2, segunda permuta��o, dessa vez aplicada as chaves ap�s o bitshift, reduzindo as 16 chaves de 56 bits, para 16 de 48
    14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

int E[] ={
    //Tabela para realizar mais uma permuta��o, porem dessa vez expandindo a entrada, aplicada aos 32 bits da direita do bloco de texto
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

//8 matrizes para realizar o embaralhamento e redu��o do texto durante a criptografia
int S1[4][16] ={
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
};

int S2[4][16] ={
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
};

int S3[4][16] ={
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
};

int S4[4][16] ={
    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
};

int S5[4][16] ={
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
};

int S6[4][16] ={
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
};

int S7[4][16]={
    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
};

int S8[4][16]={
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};



int SP[] = {
    // Realiza mais uma permuta��o no texto, usando o texto embaralhado e reduzido ap�s passar pelas s-box
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
    };

int FP[] ={
    // realiza a ultima permuta��o no texto, rearranjando ele apos a criptografia ter sido feita
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

FILE *ptFILE;
uint8_t key56[56];
uint8_t key48[17][48];
uint8_t Right[17][32], Left[17][32], IPtext[64], EXPtext[48], XORtext[48], XTextSBOX2[32], XTextSBOX[8][6],PBoxResult[32],CIPHER[64],FinalPtext[64];

//Escopo de funcoes
void getKeys();
void create16Keys(uint8_t key[]);
void key64to56(uint8_t pos, uint8_t bit);
void keysLeftShift(uint8_t esquerda[17][28], uint8_t direita[17][28]);
void key56to48(uint8_t round, uint8_t pos, uint8_t bit);
unsigned int getFileSize();
void convertCharToBits();
void convertToBinary(int8_t ch);
void encrypt_decrypt(unsigned int size, short int mode);
void initialPermutation(unsigned int pos, short int text);
void cipher(uint8_t round, uint8_t mode);
void expansionFunction(uint8_t pos, uint8_t text);
void SBox(uint8_t XORtext[]);
void F1(uint8_t Case);
void to4Bits(uint8_t n);
void PBox(uint8_t pos, uint8_t text);
void finalPermutation(uint8_t pos, uint8_t text);
void bitToCharWrite(uint8_t bits[]);

int main(){
    // destroi o conteudo desses arquivos de execucoes passadas
    ptFILE = fopen("result.txt", "wb+");
    fclose(ptFILE);

    ptFILE = fopen("decrypted.txt", "wb+");
    fclose(ptFILE);

    ptFILE = fopen("cipher.txt", "wb+");
    fclose(ptFILE);

    getKeys();
    convertCharToBits();
    unsigned int fileSize = getFileSize();
    encrypt_decrypt(fileSize,0);
    encrypt_decrypt(fileSize,1);


    return 0;
}

void getKeys(){
    FILE* keyFile = fopen("key.txt", "rb");
    uint8_t key[64], i=0;
    uint8_t ch;
    while(1){
        ch = getc(keyFile);
        if(ch==255) break;
        key[i++] = ch - 48;//pega char por char no arquivo da key binaria, por ex "0", que eh = 48
    }
    create16Keys(key);
    fclose(keyFile);
}

void create16Keys(uint8_t key[]){
    uint8_t i;
    uint8_t esquerda[17][28], direita[17][28], _16keys56[17][56];

    for(i=0;i<64;i++) key64to56(i,key[i]);

    for(i=0;i<56;i++){
        if(i<28) esquerda[0][i]=key56[i];
        else direita[0][i-28]=key56[i];
    }
    keysLeftShift(esquerda, direita);
}

void key64to56(uint8_t pos, uint8_t bit){
    //funcao para realizar a primeira permutacao
    uint8_t i;
    pos+=1;
    for(i=0;i<56;i++) if(PC1[i] == pos) break;
    key56[i] = bit;
}

void keysLeftShift(uint8_t esquerda[17][28], uint8_t direita[17][28]){
    uint8_t round, i, j, backup[17][2], _16keys56[17][56];

    for(round=0;round<16;round++){//bitshift resumidamente

        int shift = SHIFTS[round];

        for(i=0;i<shift;i++){//salva o primeiro, ou o primeiro e o segundo bit da esquerda
            backup[round][i] = esquerda[round][i];
        }for(i=0;i<(28 - shift);i++){//faz o deslocamento dos bits um pra tras, indicado pela tabela de bit shift
            esquerda[round+1][i] = esquerda[round][i + shift];
        }for(i=(28-shift), j=0;i<28;i++, j++){//insere o primeiro, ou o primeiro e o segundo bit no final, na direita
            esquerda[round+1][i] = backup[round][j];
        }


        for(i=0;i<shift;i++){//salva o primeiro, ou o primeiro e o segundo bit da esquerda
            backup[round][i] = direita[round][i];
        }for(i=0;i<(28 - shift);i++){//faz o deslocamento dos bits um pra tras, indicado pela tabela de bit shift
            direita[round+1][i] = direita[round][i + shift];
        }for(i=(28-shift), j=0;i<28;i++, j++){//insere o primeiro, ou o primeiro e o segundo bit no final, na direita
            direita[round+1][i] = backup[round][j];
        }
    }

    for(round=0;round<17;round++){ //junta todas as 16 metades em 16 keys, incluindo a primeira chave original splitada;
        for(i=0;i<56;i++){
            if(i<28) _16keys56[round][i] = esquerda[round][i];
            else _16keys56[round][i] = direita[round][i-28];
        }
    }


    for(round=1;round<17;round++) for(i=0;i<56;i++) key56to48(round, i, _16keys56[round][i]);

}
// da pra matar a key56 global, enviando ela como parametro para essa func aq, ja que eu so uso ela temporariamente
void key56to48(uint8_t round, uint8_t pos, uint8_t bit){
    //funcao para permutar as 16 keys de 56 bits em 16 keys de 48 bits
    uint8_t i;
    pos+=1;
    for(i=0;i<48;i++) if(PC2[i] == pos) break;
    key48[round][i] = bit;
}

unsigned int getFileSize(){
    FILE *input = fopen("bits.txt","rb");
    fseek(input, 0, SEEK_END);
    unsigned int size = ftell(input);
    fclose(input);
    return size;
}

void convertCharToBits(){
    uint8_t ch = 0;
    FILE *input = fopen("input.txt","rb");
    ptFILE = fopen("bits.txt","wb+");
    while(1){
        ch = getc(input);
        if(ch==255) break; // se chegar no EOF, que vem como -1 em valores assinados, em nao assinados vem como 255;
        convertToBinary(ch);
    }
    fclose(input);
    fclose(ptFILE);
}

void convertToBinary(int8_t ch){
    uint8_t bit, mask;
    int8_t i;
    for(i=7;i>=0;i--){
        mask = 1 << i; //define uma mascara usando left shift binario por exemplo, para i = 7, mask = 128, em binario (10000000)
        bit = ch & mask; //aqui ele compara o numero ch com mask usando o operador &
        if(bit==0) fprintf(ptFILE, "0");
        else fprintf(ptFILE, "1");
    }

}

void encrypt_decrypt(unsigned int size, short int mode){
    FILE *inputFile = (mode==0) ? fopen("bits.txt","rb") : fopen("cipher.txt","rb");//operador ternario para trocar o arquivo, dependendo do mode.
    ptFILE = (mode==0) ? fopen("cipher.txt","ab+") : fopen("decrypted.txt","ab+");
    unsigned int blocks,i = 0,j,p;
    unsigned char ch;
    blocks =(size%64==0) ? size/64: size/64 +1;
    int *bits = (int *)calloc(sizeof(int),(blocks*64)), round;

    while(1){ //pega todos os bits de bits.txt e salva em um vetor
        ch = getc(inputFile);
        if(ch==255) break;
        bits[i++] = ch - 48;
    }

    for(i=0;i<blocks;i++){//vai rodar para cada bloco de 64 bits
//o iptext, ta diferente
        for(p=i*64;p<(i+1)*64;p++) initialPermutation(p,bits[p]);//envia bloco por bloco para permutar

        for(j = 0; j < 64; j++){
            if(j < 32) Left[0][j] = IPtext[j];
            else Right[0][j-32] = IPtext[j];
        }

        for(round=1;round<17;round++){
            cipher(round,mode);/////////
            for(j=0;j<32;j++) Left[round][j] = Right[round-1][j];
        }

        for(j = 0; j < 64; j++){
            if(j < 32) CIPHER[j] = Right[16][j];
            else CIPHER[j] = Left[16][j - 32];
            finalPermutation(j, CIPHER[j]);
        }
        for(j=0;j<64;j++){
            fprintf(ptFILE, "%d",FinalPtext[j]);
        }

        printf("%d \n",i);
    fclose(ptFILE);
    fclose(inputFile);
    }
    printf("\n",i);
    if (mode==1){
        bitToCharWrite(FinalPtext);
    }
    
}

void initialPermutation(unsigned int pos, short int bit){
    uint8_t i;
    pos+=1;
    for(i=0;i<64;i++) if (IP[i] == pos) break;
    IPtext[i] = bit;
    printf("%d",IPtext[i]);
}

void cipher(uint8_t round, uint8_t mode){
    int i;

    for(i=0;i<32;i++) expansionFunction(i, Right[round - 1][i]);//envio a parte direita para a permutacao e expancao

    for(i=0;i<48;i++){
        if(mode==0) XORtext[i] = (EXPtext[i] ^ key48[round][i]); //aqui ele faz xor com a key e com o texto expandido na ordem crescente, para criptografia
        else XORtext[i] = (EXPtext[i] ^ key48[17 - round][i]); //para descriptografar, ele faz em ordem decrescente
    }
//a partir do xortext[19] fica diferente
    SBox(XORtext);

    for(i=0;i<32;i++){
        PBox(i, XTextSBOX2[i]);
        Right[round][i] = Left[round-1][i] ^ PBoxResult[i]; // LADO DIREITO DO ROUND CIFRADO
    }
}

void expansionFunction(uint8_t pos, uint8_t bit){
    int i;
    pos+=1;
    for(i=0;i<48;i++) if(E[i]==pos) break;
    EXPtext[i] = bit;
}

void SBox(uint8_t XORtext[]){
    int i,j,pos = 0;

    for(i=0;i<8;i++) for(j=0;j<6;j++) XTextSBOX[i][j] = XORtext[pos++]; //separa o texto xor do round em uma matriz 8 x 6, sendo 8 linhas de 6 colunas cada.

    for(i=0;i<8;i++) F1(i);//faz todo o processo da sbox, reduzindo de 48 para 32bits;

}

void F1(uint8_t Case){
    int8_t linha = 0, coluna= 0, value;
    //O ERRO TA AQUI, A MENSAGEM TA SENDO CRIPTOGRAFADA ERRADO, POIS OS VALORES DE LINHA E COLUNA NAO ESTAO CORRETOS.

    /*VALORES ESPERADOS
    2 12
    0 9
    2 7
    1 1
    0 13
    0 14
    3 7
    3 15
    */

    linha = (XTextSBOX[Case][0] << 1) + XTextSBOX[Case][5];
    coluna = (XTextSBOX[Case][1] << 3) + (XTextSBOX[Case][2] << 2) + (XTextSBOX[Case][3] << 1) + XTextSBOX[Case][4];

    switch (Case){
        case 0:
            value = S1[linha][coluna];
            break;
        case 1:
            value = S2[linha][coluna];
            break;
        case 2:
            value = S3[linha][coluna];
            break;
        case 3:
            value = S4[linha][coluna];
            break;
        case 4:
            value = S5[linha][coluna];
            break;
        case 5:
            value = S6[linha][coluna];
            break;
        case 6:
            value = S7[linha][coluna];
            break;
        case 7:
            value = S8[linha][coluna];
            break;
    }
    to4Bits(value); // essa funcao passa o valor recebido, para um binario de 4 digitos, e adiciona no vetor
}

void to4Bits(uint8_t n){
    uint8_t mask, bit, deslocamento = 0;
    int8_t j;
    if (deslocamento%32==0) deslocamento =0;
    for(j=3;j>=0;j--){
        mask = 1 << j;
        bit = n  & mask;
        XTextSBOX2[3 - j + deslocamento] = (bit==0) ? 0: 1;
    }
    deslocamento+=4;
}

void PBox(uint8_t pos, uint8_t text){
    uint8_t i;
    pos+=1;
    for(i=0;i<32;i++) if(SP[i] == pos) break;
    PBoxResult[i] = text;
}

void finalPermutation(uint8_t pos, uint8_t text){
    uint8_t i;
    pos+=1;
    for(i=0;i<64;i++) if(FP[i] == pos) break;
    FinalPtext[i] = text;
}

void bitToCharWrite(uint8_t bits[]){
    int8_t i,j,ch;
    FILE *result = fopen("result.txt","wb");
    for(i=0;i<8;i++) {
        ch = 0;
        for(j=7;j>=0;j--){
            ch += bits[i] << i;
        }
        fprintf(result,"%c",ch);
    }
    fclose(result);
}
