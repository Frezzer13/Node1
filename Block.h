#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <ctime>
#include "Transaction.h"
#include <nlohmann/json.hpp>

class Block {
public:
    std::string prevHash;                  // Hash of the previous block
    std::string blockHash;                 // Hash of the current block
    std::vector<Transaction> transactions; // List of transactions in the block
    std::time_t timestamp;                 // Block creation time
    int nonce;                             // Nonce used for proof-of-work
    int difficulty;                        // Mining difficulty (number of leading zeros required)

    // Default constructor for deserialization.
    Block();

    // Parameterized constructor.
    Block(const std::vector<Transaction>& transactions, const std::string& prevHash, int difficulty);

    // Mine the block (find a nonce such that the hash meets the difficulty).
    std::string mineBlock();

    // Generate the block's hash from its contents.
    std::string generateHash() const;

    // Compute a SHA-256 hash of a given string.
    std::string sha256(const std::string& data) const;

    // JSON serialization.
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);

    // Static function to create a common genesis block.
    // In Block.h
    static Block createGenesisBlock(int difficulty);
};

#endif // BLOCK_H
