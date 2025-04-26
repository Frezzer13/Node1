#ifndef WALLET_H
#define WALLET_H

#include <string>
#include <openssl/evp.h>
#include "Vote.h"  // Assumes Vote class is defined

class Wallet {
public:
    Wallet(const std::string& voterId);
    ~Wallet();

    std::string getVoterId() const { return voterId; }
    EVP_PKEY* getPublicKey() const { return publicKey; }
    // Helper to get public key as a PEM string.
    std::string getPublicKeyString() const;
    // Helper to get private key as a PEM string.
    std::string getPrivateKeyString() const;

    void printWalletData() const;
    EVP_PKEY* getPrivateKey() const {
        return privateKey;
    }
private:
    std::string voterId;
    EVP_PKEY* publicKey;
    EVP_PKEY* privateKey;
    void generateKeys();

};

#endif // WALLET_H
