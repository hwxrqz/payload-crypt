The code examples provided allow you to encrypt the payload and embed it in the .rdata section.

**XOR Usage**

```main_encrypt.c``` ecnrypts the payload with the XOR algorithm and outputs a C-friendly encrypted byte sequence.

```main_decrypt.c``` must contain this encrypted payload. The code provided demonstrates a working example of dynamically decrypting and running the payload by creating an executable address space.

**RC4 Usage**

```main_encrypt.c``` encrypts the payload with the RC4 algorithm and outputs a C-friendly encrypted byte sequence.

```main_decrypt.c``` must contain this encrypted payload. The code provided demonstrates a working example of dynamically decrypting and running the payload by creating an executable address space.

The RC4 algorithm code was taken from here:
```https://www.oryx-embedded.com/doc/rc4_8c_source.html```

**AES Usage**

```main_ecnrypt.c``` encrypts the payload with the AES-256-CBC algorithm and outputs a C-friendly encrypted byte sequence. AES has been realised with bCrypt Library
```main_decrypt.c``` must contain this encrypted payload. The code provided demonstrates a working example of dynamically decrypting and running the payload by creating an executable address space.

The AES algorithm code was realised with bCrypt library
