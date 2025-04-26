#include "Vote.h"
#include <sstream>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <openssl/err.h>

// For convenience with JSON
using json = nlohmann::json;

// Default Constructor
Vote::Vote() : voterId(""), candidateId(""), signature(""), nonce(0), publicKey("") {}

// Parameterized constructor
Vote::Vote(const std::string& voterId, const std::string& candidateId, int nonce)
    : voterId(voterId), candidateId(candidateId), nonce(nonce), signature(""), publicKey("") {}

// Sign the vote using the provided Ed25519 private key
void Vote::sign(EVP_PKEY* privateKey) {
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX.");
    }

    // Проверяем, что ключ имеет тип Ed25519.
    if (EVP_PKEY_base_id(privateKey) != EVP_PKEY_ED25519) {
        EVP_MD_CTX_free(mdCtx);
        throw std::runtime_error("Private key is not of type Ed25519.");
    }

    // Для Ed25519 передаем nullptr в качестве алгоритма digest.
    if (EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, privateKey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdCtx);
        throw std::runtime_error("Failed to initialize DigestSign for Ed25519.");
    }

    // Формируем строку данных для подписи.
    std::stringstream dataStream;
    dataStream << voterId << "|" << candidateId << "|" << nonce;
    std::string dataToSign = dataStream.str();

    size_t sigLen = 0;
    // Определяем требуемую длину подписи.
    if (EVP_DigestSign(mdCtx, nullptr, &sigLen,
        reinterpret_cast<const unsigned char*>(dataToSign.data()),
        dataToSign.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdCtx);
        throw std::runtime_error("Failed to determine signature size for Ed25519.");
    }

    // Выделяем буфер и генерируем подпись.
    std::vector<unsigned char> sig(sigLen);
    if (EVP_DigestSign(mdCtx, sig.data(), &sigLen,
        reinterpret_cast<const unsigned char*>(dataToSign.data()),
        dataToSign.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdCtx);
        throw std::runtime_error("Failed to generate signature for Ed25519.");
    }
    sig.resize(sigLen);

    // Кодируем подпись в Base64.
    signature = base64Encode(std::string(reinterpret_cast<char*>(sig.data()), sig.size()));
    EVP_MD_CTX_free(mdCtx);
}

// Verify the vote using the provided Ed25519 public key
bool Vote::verify(EVP_PKEY* publicKey) const {
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX.");
    }
    // Для Ed25519 передаем nullptr вместо digest.
    if (EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, publicKey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdCtx);
        throw std::runtime_error("Failed to initialize DigestVerify for Ed25519.");
    }

    std::stringstream dataStream;
    dataStream << voterId << "|" << candidateId << "|" << nonce;
    std::string dataToVerify = dataStream.str();

    // Декодируем Base64-подпись.
    std::string decodedSignature = base64Decode(signature);

    int result = EVP_DigestVerify(
        mdCtx,
        reinterpret_cast<const unsigned char*>(decodedSignature.data()),
        decodedSignature.size(),
        reinterpret_cast<const unsigned char*>(dataToVerify.data()),
        dataToVerify.size()
    );
    EVP_MD_CTX_free(mdCtx);
    return (result == 1);
}

// Convert the vote to JSON format
json Vote::toJson() const {
    nlohmann::json j;
    j["voterId"] = voterId;
    j["candidateId"] = candidateId;
    j["nonce"] = nonce;
    j["signature"] = signature;
    j["publicKey"] = publicKey; // Include the public key in the JSON
    return j;
}

// Load vote data from JSON
void Vote::fromJson(const nlohmann::json& j) {
    voterId = j.at("voterId").get<std::string>();
    candidateId = j.at("candidateId").get<std::string>();
    nonce = j.at("nonce").get<int>();
    signature = j.at("signature").get<std::string>();
    publicKey = j.at("publicKey").get<std::string>();
}

// Encode binary data to a Base64 string
std::string Vote::base64Encode(const std::string& binaryData) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!bio || !b64) {
        if (bio) BIO_free(bio);
        if (b64) BIO_free(b64);
        throw std::runtime_error("Failed to create BIO for Base64 encoding.");
    }
    // Disable newlines in the output.
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);

    if (BIO_write(b64, binaryData.data(), binaryData.size()) <= 0) {
        BIO_free_all(b64);
        throw std::runtime_error("Failed to write data for Base64 encoding.");
    }
    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        throw std::runtime_error("Failed to flush BIO for Base64 encoding.");
    }

    BUF_MEM* bufferPtr = nullptr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return encodedData;
}

// Decode a Base64-encoded string into binary data
std::string Vote::base64Decode(const std::string& encodedData) {
    BIO* bio = BIO_new_mem_buf(encodedData.data(), static_cast<int>(encodedData.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!bio || !b64) {
        if (bio) BIO_free(bio);
        if (b64) BIO_free(b64);
        throw std::runtime_error("Failed to create BIO for Base64 decoding.");
    }
    // Disable newlines in Base64 input.
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);

    std::string decoded;
    std::vector<char> buffer(128);
    int bytesRead = 0;
    while ((bytesRead = BIO_read(b64, buffer.data(), static_cast<int>(buffer.size()))) > 0) {
        decoded.append(buffer.data(), bytesRead);
    }
    BIO_free_all(b64);
    return decoded;
}
