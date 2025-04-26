#ifndef KEYUTILS_H
#define KEYUTILS_H

#include <string>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

// Inline helper function to load a private key from a PEM string.
inline EVP_PKEY* loadPrivateKey(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key.");
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        throw std::runtime_error("Failed to load private key from PEM.");
    }
    return key;
}

// Inline helper function to load a public key from a PEM string.
inline EVP_PKEY* loadPublicKey(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for public key.");
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        throw std::runtime_error("Failed to load public key from PEM.");
    }
    return key;
}

#endif // KEYUTILS_H
