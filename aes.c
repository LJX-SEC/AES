//Coded by juhye0p
#include "aes.h"

void switchState(int idx){
    int i = idx;

    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            state[y][x] = binary[i];
            i++;
        }
    }
}

void switchBinary(int idx){
    int i = idx;

    for(int x = 0; x < 4; x++){
        for(int y = 0; y < 4; y++){
            binary[i] = state[y][x];
            i++;
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
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[i][j] = s_box[getMost4bits(state[i][j])][getLeast4bits(state[i][j])];
        }
    }
}

void shiftRows(){
    unsigned char temp = 0x00;
    
    //1 shift
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    //2 shift
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    //3 shift
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}


void mixColumns(){
    unsigned char Tmp, Tm, t;
    for (int i = 0; i < 4; i++){  
        t   = state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        Tm  = state[0][i] ^ state[1][i];    Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp;
        Tm  = state[1][i] ^ state[2][i];    Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp;
        Tm  = state[2][i] ^ state[3][i];    Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp;
        Tm  = state[3][i] ^ t;  Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp;
    }
}

void addRoundKey(int round){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[j][i] ^= roundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

void keyScheduling(){
    unsigned char tmp[4] = {0x00, };
    unsigned char t = 0x00;
    int idx, ridx;

    //first key
    for (int i = 0; i < Nk; i++){
        roundKey[(i * 4) + 0] = key[(i * 4) + 0];
        roundKey[(i * 4) + 1] = key[(i * 4) + 1];
        roundKey[(i * 4) + 2] = key[(i * 4) + 2];
        roundKey[(i * 4) + 3] = key[(i * 4) + 3];
    }

    //key schduling
    for (int i = Nk; i < Nb * (Nr + 1); i++){
        idx = (i - 1) * 4;
        tmp[0]=roundKey[idx + 0];
        tmp[1]=roundKey[idx + 1];
        tmp[2]=roundKey[idx + 2];
        tmp[3]=roundKey[idx + 3];

        if (i % Nk == 0){
            //rotword
            t = tmp[0];
            tmp[0] = tmp[1];
            tmp[1] = tmp[2];
            tmp[2] = tmp[3];
            tmp[3] = t;

            //subword
            tmp[0] = s_box[getMost4bits(tmp[0])][getLeast4bits(tmp[0])];
            tmp[1] = s_box[getMost4bits(tmp[1])][getLeast4bits(tmp[1])];
            tmp[2] = s_box[getMost4bits(tmp[2])][getLeast4bits(tmp[2])];
            tmp[3] = s_box[getMost4bits(tmp[3])][getLeast4bits(tmp[3])];

            tmp[0] = tmp[0] ^ rcon[i/Nk];
        }  
        ridx = i * 4; idx = (i - Nk) * 4;
        roundKey[ridx + 0] = roundKey[idx + 0] ^ tmp[0];
        roundKey[ridx + 1] = roundKey[idx + 1] ^ tmp[1];
        roundKey[ridx + 2] = roundKey[idx + 2] ^ tmp[2];
        roundKey[ridx + 3] = roundKey[idx + 3] ^ tmp[3];
    }
}

unsigned char xtime(unsigned char byte){
    return ((byte << 1) ^ (((byte >> 7) & 1) * 0x1b));
}

void phex(unsigned char* ptr, int size){
    int c = 0;
    for(int i = 0; i < size; i++){
        if(c != 0 && c % 16 == 0){
            printf("\n");
            c = 0;
        }
        printf("%02x", ptr[i]);
        c++;
    }
    printf("\n");
}

void encrypt(){
    addRoundKey(0);

    for(int round = 1; ; round++){
        subBytes();
        shiftRows();
        if(round == Nr){
            break;
        }
        mixColumns();
        addRoundKey(round);
    }

    addRoundKey(Nr);
}

int main(){
    char* fileName = "sample";
    char* keyName = "key.bin";
    char* encryptName = "sample.ENCRYPT";

    int tempSize = 0;

    printf("[*] AES-128 ECB PKCS#7 padding\n");

    FILE *hFile = NULL;
    FILE *hKey = NULL;

    hFile = fopen(fileName, "rb");
    hKey = fopen(keyName, "rb");

    if(hFile != NULL && hKey != NULL){
        printf("[*] binary and key were detected!\n");

        fseek(hFile, 0, SEEK_END);
        fseek(hKey, 0, SEEK_END);

        binarySize = ftell(hFile);
        keySize = ftell(hKey);

        if(binarySize <= 0 || keySize <= 0){
            //invalid binary size
            printf("[!] invalid binary size!\n");
            fclose(hFile);
            fclose(hKey);
            exit(-1);
        }
        else if(keySize != Nkl){
            //invalid key size
            printf("[!] invalid key size!\n");
            fclose(hFile);
            fclose(hKey);
            exit(-1);
        }

        //store size for padding
        tempSize = binarySize;

        //get padded binary size
        padData = (Nkl - (binarySize % Nkl));
        binarySize += padData;
        
        binary = malloc(binarySize);
        key = malloc(keySize);
        printf("[*] allocating binary and key memory complete!\n");

        rewind(hFile);
        rewind(hKey);

        fread(binary, tempSize, sizeof(unsigned char), hFile);
        fread(key, keySize, sizeof(unsigned char), hKey);

        //padding binary
        if(tempSize < binarySize){
            for(int idx = tempSize; idx < binarySize; idx++){
                binary[idx] = padData;
            }
        }

        printf("[*] %d blocks detected!\n", (int)(binarySize / 16));

        printf("[*] storing binary and key complete!\n\n");
        fclose(hFile);
        fclose(hKey);
        
        printf("[+] key : ");
        phex(key, keySize);
        printf("\n");

        printf("[+] input : \n");
        phex(binary, tempSize);
        printf("\n");

        printf("[+] padded plaintext : \n");
        phex(binary, binarySize);
        printf("\n");

        printf("[*] encryption\n");
        
        //AES encryption
        printf("[*] key scheduling\n");
        keyScheduling();

        free(key);

        printf("[+] scheduled key : \n");
        phex(roundKey, Nkl * (10 + 1));
        printf("\n");

        for(int idx = 0; idx < binarySize; idx += Nkl){
            switchState(idx);
            printf("[+] %d block input : ", (idx/Nkl) + 1);
            phex((unsigned char *)state, 16);

            encrypt();

            printf("[+] %d block output out : ", (idx/Nkl) + 1);
            phex((unsigned char *)state, 16);
            switchBinary(idx);
        }
        printf("\n");

        printf("[+] cipher : \n");
        phex(binary, binarySize);
        
        printf("\n");

        #if writeEncFile
            //create encrypted file
            FILE *hEncFile = NULL;
            printf("[.] creating encrypted file..\n");
            
            if((hEncFile = fopen(encryptName, "wb")) != NULL){
                size_t writtenBytes = fwrite(binary, sizeof(unsigned char), binarySize / sizeof(unsigned char), hEncFile);
                printf("[*] %lld bytes written\n", writtenBytes);

                if(writtenBytes < binarySize){
                    printf("[*] some bytes missing..\n");
                }
                fclose(hEncFile);
            }
            else{
                printf("[-] failed to create encrypted file..\n");
            }
        #endif

        free(binary);
        printf("[*] done\n");
    }
    
    else{
        //file not found
        printf("[-] binary or key is missing!\n");
        exit(-1);
    }

    return 0;
}