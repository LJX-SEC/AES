//Coded by LJX
//AES-128
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

unsigned char state[4][4] = {0x00, };
unsigned char tempKey[4][4] = {0x00, };
long long int binarySize = 0x00;
unsigned char keySize = 0x00;

unsigned char *binary = (unsigned char *)0x00;
unsigned char *key = (unsigned char *)0x00;

const int aes_bits = 16; /* AES-128 */

const unsigned char s_box[0x10][0x10] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

const unsigned char mulColumns_[4][4] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
};

const unsigned char rcon[4][10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void switchState(int idx);
void switchBinary(int idx);

void switchTemp();
void switchKey();

unsigned char getMost4bits(unsigned char byte);
unsigned char getLeast4bits(unsigned char byte);

void subBytes();
void shiftRows();
void mixColumns();
void addRoundKey();

void keyScheduling(unsigned char idx);

void switchState(int idx){
    int i = idx;

    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            state[x][y] = binary[i];
            i++;
        }
    }
}

void switchBinary(int idx){
    int i = idx;

    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            binary[i] = state[x][y];
            i++;
        }
    }
}

void switchTemp(){
    int idx = 0;

    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            tempKey[x][y] = key[idx];
            idx++;
        }
    }
}

void switchKey(){
    int idx = 0;

    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            key[idx] = tempKey[x][y];
            idx++;
        }
    }
}

unsigned char getMost4bits(unsigned char byte){
    return ((unsigned char)0xf0 & byte) >> 4;
}

unsigned char getLeast4bits(unsigned char byte){
    return ((unsigned char)0x0f & byte);
}


void subBytes(){
    unsigned char most_4_bits = 0x00;
    unsigned char least_4_bits = 0x00;

    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            most_4_bits = getMost4bits(state[i][j]);
            least_4_bits = getLeast4bits(state[i][j]);

            state[i][j] = s_box[most_4_bits][least_4_bits];
        }
    }
}

void shiftRows(){
    unsigned char temp = 0x00;
    
    /* 1 shift */
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    /* 2 shift */
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    /* 3 shift */
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void mixColumns(){
    bool isCarry = false;
    const int carryCheck = 0xff;
    
    unsigned char temp[4] = {0x00, };
    int c_byte = 0x00;

    for(int i = 0; i < 4; i++){
        /* Initalize Temp Buffer */
        temp[0] = 0x00;
        temp[1] = 0x00;
        temp[2] = 0x00;
        temp[3] = 0x00;

        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                /* multiply 3 */
                if(mulColumns_[j][k] == 0x03){
                    c_byte = state[k][i] * 2;
                    isCarry = (c_byte > carryCheck) ? true : false;
                
                    c_byte = c_byte & 0xff;
                    /* Carry */
                    if(isCarry){
                        c_byte ^= 0x1b;
                    }

                    c_byte ^= state[k][i];
                }
                else{
                    c_byte = state[k][i] * mulColumns_[j][k];
                    isCarry = (c_byte > carryCheck) ? true : false;
                
                    c_byte = c_byte & 0xff;
                    /* Carry */
                    if(isCarry){
                        c_byte ^= 0x1b;
                    }
                }
                /* XOR All Of Columns */
                temp[j] ^= c_byte;
            }
        }

        /* Store The Cipher Byte */
        state[0][i] = temp[0];
        state[1][i] = temp[1];
        state[2][i] = temp[2];
        state[3][i] = temp[3];
    }
}

void addRoundKey(){
    int idx = 0;

    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[i][j] ^= key[idx];
            idx++;
        }
    }
}

void keyScheduling(unsigned char idx){
    unsigned char temp = 0x00;

    unsigned char most_4_bits = 0x00;
    unsigned char least_4_bits = 0x00;

    switchTemp();

    /* RotWord */
    temp = tempKey[0][3];
    tempKey[0][3] = tempKey[1][3];
    tempKey[1][3] = tempKey[2][3];
    tempKey[2][3] = tempKey[3][3];
    tempKey[3][3] = temp;

    /* SubBytes */
    for(int i = 0; i < 4; i++){
        most_4_bits = getMost4bits(tempKey[i][3]);
        least_4_bits = getLeast4bits(tempKey[i][3]);

        tempKey[i][3] = s_box[most_4_bits][least_4_bits];
    }

    /* Cipher Key(Word) ^ Last Key(Word) ^ Rcon(Word) */
    for(int i = 0; i < 4; i++){
        tempKey[i][0] ^= tempKey[i][3];
        tempKey[i][0] ^= rcon[i][idx];
    }

    /* Cipher Key(Word) ^ Previous Word */
    for(int i = 1; i < 4; i++){
        for(int j = 0; j < 4; j++){
            tempKey[j][i] ^= tempKey[j][i - 1];
        }
    }

    switchKey();
}

int main(){
    char* fileName = "sample";
    char* keyName = "key-128.bin";
    char* encryptName = "sample.ENCRYPT";

    int tempSize = 0;

    printf("[ AES Encryption ]\n\n");

    FILE *hFile = NULL;
    FILE *hKey = NULL;

    hFile = fopen(fileName, "rb");
    hKey = fopen(keyName, "rb");

    if(hFile != NULL && hKey != NULL){
        printf("[*] Binary and key were detected!\n");

        fseek(hFile, 0, SEEK_END);
        fseek(hKey, 0, SEEK_END);

        binarySize = ftell(hFile);
        keySize = ftell(hKey);

        if(binarySize <= 0 || keySize <= 0){
            /* Invalid Binary Size */
            printf("[!] Invalid binary size!\n");
            fclose(hFile);
            fclose(hKey);
            exit(-1);
        }
        else if(keySize != aes_bits){
            /* Invalid Key Size */
            printf("[!] Invalid key size!\n");
            fclose(hFile);
            fclose(hKey);
            exit(-1);
        }

        /* Store Size For Padding */
        tempSize = binarySize;

        /* Get Padded Binary Size */
        if((binarySize % aes_bits) != 0){
            binarySize = ((binarySize + (aes_bits - 1)) & ~(aes_bits - 1));
        }
        
        binary = malloc(binarySize);
        key = malloc(keySize);
        printf("[+] Allocating binary and key memory complete!\n");

        rewind(hFile);
        rewind(hKey);

        fread(binary, tempSize, sizeof(unsigned char), hFile);
        fread(key, keySize, sizeof(unsigned char), hKey);

        /* Padding Binary - PKCS#7 Padding */
        if(tempSize < binarySize){
            int paddingData = binarySize - tempSize;
            for(int idx = tempSize; idx < binarySize; idx++){
                binary[idx] = paddingData;
            }
        }

        printf("[*] %d blocks detected!\n", (int)(binarySize / 16));

        printf("[+] Storing binary and key complete!\n\n");
        fclose(hFile);
        fclose(hKey);
        
        printf("Key : ");
        for(int i = 0; i < keySize; i++){
            printf("%02X ", key[i]);
        }
        printf("\n");

        printf("Plaintext : ");
        for(int i = 0; i < binarySize; i++){
            printf("%02X ", binary[i]);
        }
        printf("\n\n");

        printf("[*] Start encryption\n");
        
        /* Encrytion */

        /* AddRoundKey */
        for(int idx = 0; idx < binarySize; idx += 16){
            switchState(idx);
            addRoundKey();
            switchBinary(idx);
        }
        
        /* 10 Rounds */
        for(int round = 0; round < 10; round++){
            /* SubBytes */
            for(int idx = 0; idx < binarySize; idx += 16){
                switchState(idx);
                subBytes();
                switchBinary(idx);
            }

            /* ShiftRows */
            for(int idx = 0; idx < binarySize; idx += 16){
                switchState(idx);
                shiftRows();
                switchBinary(idx);
            }
            
            if(round < 9){
                /* MixColumns */
                for(int idx = 0; idx < binarySize; idx += 16){
                    switchState(idx);
                    mixColumns();
                    switchBinary(idx);
                }
            }

            /* KeyScheduling */
            switchTemp();
            keyScheduling(round);
            switchKey();

            /* AddRoundKey */
            for(int idx = 0; idx < binarySize; idx += 16){
                switchState(idx);
                addRoundKey();
                switchBinary(idx);
            }
        }

        printf("Encrypted : ");
        for(int i = 0; i < binarySize; i++){
            printf("%02X ", binary[i]);
        }
        printf("\n\n");

	FILE* hEfile = NULL;
	hEfile = fopen(encryptName, "wb");
	printf("[.] Writing encrypted file..\n");
	fwrite(binary, sizeof(unsigned char), binarySize, hEfile);
	fclose(hEfile);
        
        free(binary);
        free(key);

	printf("[+] Complete\n");
    }
    
    else{
        /* Not Found */
        printf("[-] Binary or key is missing!\n");
        exit(-1);
    }

    return 0;
}
