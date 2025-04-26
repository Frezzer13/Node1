#include "Block.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>

using json = nlohmann::json;

Block::Block()
    : prevHash(""), blockHash(""), timestamp(0), nonce(0), difficulty(0)
{
    // Default constructor for JSON deserialization.
}

Block::Block(const std::vector<Transaction>& transactions, const std::string& prevHash, int difficulty)
    : transactions(transactions), prevHash(prevHash), timestamp(std::time(nullptr)), nonce(0), difficulty(difficulty)
{
    // Mine the block immediately upon creation.
    blockHash = mineBlock();
}

std::string Block::mineBlock() {
    std::string target(difficulty, '0'); // For example, "0000" for difficulty 4.
    blockHash = generateHash();
    while (blockHash.substr(0, difficulty) != target) {
        nonce++;
        blockHash = generateHash();
    }
    std::cout << "Block mined! Nonce: " << nonce << ", Hash: " << blockHash << std::endl;
    return blockHash;
}

std::string Block::generateHash() const {
    std::stringstream ss;
    // Use delimiters to separate fields.
    ss << prevHash << "|" << timestamp << "|" << nonce << "|" << difficulty;
    for (const auto& tx : transactions) {
        ss << "|" << tx.voterId << "|" << tx.candidateId << "|" << tx.nonce << "|" << tx.signature;
    }
    return sha256(ss.str());
}

std::string Block::sha256(const std::string& data) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX.");
    }
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (!EVP_DigestInit_ex(ctx, md, nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed.");
    }
    if (!EVP_DigestUpdate(ctx, data.c_str(), data.size())) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed.");
    }
    if (!EVP_DigestFinal_ex(ctx, hash, &hashLen)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed.");
    }
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

json Block::toJson() const {
    json j;
    j["prevHash"] = prevHash;
    j["blockHash"] = blockHash;
    j["timestamp"] = timestamp;
    j["nonce"] = nonce;
    j["difficulty"] = difficulty;
    j["transactions"] = json::array();
    for (const auto& tx : transactions) {
        j["transactions"].push_back(tx.toJson());
    }
    return j;
}

void Block::fromJson(const json& j) {
    prevHash = j.at("prevHash").get<std::string>();
    blockHash = j.at("blockHash").get<std::string>();
    timestamp = j.at("timestamp").get<std::time_t>();
    nonce = j.at("nonce").get<int>();
    difficulty = j.at("difficulty").get<int>();
    transactions.clear();
    for (const auto& txJson : j.at("transactions")) {
        Transaction tx;
        tx.fromJson(txJson);
        transactions.push_back(tx);
    }
}

// Create a genesis block with fixed values.
Block Block::createGenesisBlock(int difficulty) {
    std::vector<Transaction> emptyTransactions;
    Block genesisBlock;
    genesisBlock.prevHash = "0";
    genesisBlock.timestamp = 0;   // Fixed timestamp
    genesisBlock.nonce = 0;       // Fixed nonce
    genesisBlock.difficulty = difficulty;
    genesisBlock.transactions = emptyTransactions;
    // Recompute the hash using the fixed values.
    genesisBlock.blockHash = genesisBlock.generateHash();
    return genesisBlock;
}

