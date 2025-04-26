#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

// Forward declaration of Vote.
class Vote;

class Transaction {
public:
    std::string voterId;
    std::string candidateId;
    std::string signature;
    int nonce;
    std::string publicKey;  // Included public key field

    Transaction();
    Transaction(const std::string& voterId, const std::string& candidateId, int nonce);
    // Conversion constructor from Vote.
    Transaction(const Vote& vote);
    void sign(EVP_PKEY* privateKey);
    bool verify(EVP_PKEY* publicKey) const;
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);
    static std::string base64Encode(const std::string& binaryData);
    static std::string base64Decode(const std::string& encodedData);
};

#endif // TRANSACTION_H
