#ifndef VOTE_H
#define VOTE_H

#include <string>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

class Vote {
public:
    std::string voterId;
    std::string candidateId;
    std::string signature;
    int nonce;
    std::string publicKey;  // Added field for the sender's public key

    Vote();
    Vote(const std::string& voterId, const std::string& candidateId, int nonce);
    void sign(EVP_PKEY* privateKey);
    bool verify(EVP_PKEY* publicKey) const;
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);
    static std::string base64Encode(const std::string& binaryData);
    static std::string base64Decode(const std::string& encodedData);
};

#endif // VOTE_H
