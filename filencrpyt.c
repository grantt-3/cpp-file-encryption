#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define KEY_SIZE 32
#define BLOCK_SIZE 16

int encrypt_decrypt_file(const char* input_file, const char* output_file, 
                         const unsigned char* key, const unsigned char* iv, 
                         int do_encrypt) {
    FILE *in_file, *out_file;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    // Open files
    in_file = fopen(input_file, "rb");
    out_file = fopen(output_file, "wb");
    if (!in_file || !out_file) {
        perror("File open error");
        return 0;
    }

    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, do_encrypt);

    // Process file in chunks
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in_file)) > 0) {
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_file);
            fclose(out_file);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out_file);
    }

    // Finalize encryption/decryption
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out_file);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s [encrypt/decrypt] <input> <output> <key>\n", argv[0]);
        return 1;
    }

    // Key and IV setup
    unsigned char key[KEY_SIZE];
    unsigned char iv[BLOCK_SIZE] = {0};
    strncpy((char*)key, argv[4], KEY_SIZE);
    memset(key + strlen(argv[4]), 0, KEY_SIZE - strlen(argv[4]));

    int do_encrypt = strcmp(argv[1], "encrypt") == 0;

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Perform encryption/decryption
    int result = encrypt_decrypt_file(argv[2], argv[3], key, iv, do_encrypt);

    printf("%s %s\n", 
           do_encrypt ? "Encryption" : "Decryption", 
           result ? "successful" : "failed");

    return result ? 0 : 1;
}
