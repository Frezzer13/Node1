#include "Wallet.h"
#include <iostream>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

Wallet::Wallet(const std::string& voterId)
    : voterId(voterId), publicKey(nullptr), privateKey(nullptr)
{
    generateKeys();
}

Wallet::~Wallet() {
    if (privateKey) {
        EVP_PKEY_free(privateKey);
    }
    if (publicKey) {
        EVP_PKEY_free(publicKey);
    }
}

#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>

void Wallet::generateKeys() {
    // Create a context for Ed25519 key generation.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for Ed25519.");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed for Ed25519.");
    }
    // Generate the private key.
    if (EVP_PKEY_keygen(ctx, &privateKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed for Ed25519.");
    }
    // Duplicate the private key to obtain the public key.
    publicKey = EVP_PKEY_dup(privateKey);
    if (!publicKey) {
        EVP_PKEY_free(privateKey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to duplicate public key for Ed25519.");
    }
    EVP_PKEY_CTX_free(ctx);
}


std::string Wallet::getPublicKeyString() const {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for public key conversion.");
    }
    if (PEM_write_bio_PUBKEY(bio, publicKey) != 1) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write public key to BIO.");
    }
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pubKeyStr(data, len);
    BIO_free(bio);
    return pubKeyStr;
}

std::string Wallet::getPrivateKeyString() const {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key conversion.");
    }

    // Write the private key to the BIO in PEM format.
    if (PEM_write_bio_PrivateKey(bio, privateKey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throw std::runtime_error("Failed to write private key to BIO.");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Failed to get data from BIO.");
    }

    std::string privKeyStr(data, len);
    BIO_free(bio);
    return privKeyStr;
}


void Wallet::printWalletData() const {
    std::cout << "Voter ID: " << voterId << "\n";
    // Use BIO to print the public key in PEM format.
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Failed to create BIO for public key output.\n";
        return;
    }
    if (PEM_write_bio_PUBKEY(bio, publicKey) != 1) {
        std::cerr << "Failed to write public key to BIO.\n";
        BIO_free(bio);
        return;
    }
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len > 0) {
        std::cout << "Public Key:\n" << std::string(data, len) << "\n";
    }
    BIO_free(bio);
}
