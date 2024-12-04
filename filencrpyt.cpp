#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <vector>

class FileEncryptor {
private:
    std::string key;
    std::string iv;

    // Encrypt/decrypt core function
    bool processFile(const std::string& inputFile, 
                     const std::string& outputFile, 
                     bool isEncrypt) {
        // Open input and output files
        std::ifstream inFile(inputFile, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);
        
        if (!inFile || !outFile) {
            std::cerr << "File open error!" << std::endl;
            return false;
        }

        // Initialize OpenSSL encryption context
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);

        // Convert key and IV to unsigned char
        unsigned char* ucKey = reinterpret_cast<unsigned char*>(&key[0]);
        unsigned char* ucIv = reinterpret_cast<unsigned char*>(&iv[0]);

        // Initialize encryption/decryption
        EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, ucKey, ucIv, isEncrypt);

        // Buffer for reading/writing
        std::vector<unsigned char> inBuffer(4096);
        std::vector<unsigned char> outBuffer(4096 + AES_BLOCK_SIZE);
        int inLen, outLen;

        // Process file in chunks
        while (inFile.read(reinterpret_cast<char*>(inBuffer.data()), inBuffer.size())) {
            int readCount = inFile.gcount();
            
            if (!EVP_CipherUpdate(ctx, outBuffer.data(), &outLen, 
                                   inBuffer.data(), readCount)) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
        }

        // Finalize encryption/decryption
        if (!EVP_CipherFinal_ex(ctx, outBuffer.data(), &outLen)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

        // Clean up
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

public:
    FileEncryptor(const std::string& secretKey, const std::string& initVector) 
        : key(secretKey), iv(initVector) {
        // Ensure key is 32 bytes (256 bits)
        key.resize(32, '\0');
        iv.resize(16, '\0');
    }

    bool encrypt(const std::string& inputFile, const std::string& outputFile) {
        return processFile(inputFile, outputFile, true);
    }

    bool decrypt(const std::string& inputFile, const std::string& outputFile) {
        return processFile(inputFile, outputFile, false);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] 
                  << " [encrypt/decrypt] <input_file> <output_file> <secret_key>" 
                  << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string secretKey = argv[4];

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    FileEncryptor encryptor(secretKey, "1234567890123456");  // Fixed IV for simplicity

    bool success = false;
    if (mode == "encrypt") {
        success = encryptor.encrypt(inputFile, outputFile);
    } else if (mode == "decrypt") {
        success = encryptor.decrypt(inputFile, outputFile);
    } else {
        std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
        return 1;
    }

    if (success) {
        std::cout << (mode == "encrypt" ? "Encryption" : "Decryption") 
                  << " completed successfully." << std::endl;
    } else {
        std::cerr << (mode == "encrypt" ? "Encryption" : "Decryption") 
                  << " failed." << std::endl;
        return 1;
    }

    return 0;
}
