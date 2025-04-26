#include "Blockchain.h"
#include "Block.h"
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <algorithm>  // for std::remove_if

using json = nlohmann::json;

Blockchain::Blockchain() : difficulty(4) {
    // Create and add the genesis block.
    Block genesisBlock = Block::createGenesisBlock(difficulty);
    chain.push_back(genesisBlock);
}

json Blockchain::toJson() const {
    json j;
    j["chain"] = json::array();
    for (const auto& block : chain) {
        j["chain"].push_back(block.toJson());
    }
    j["pendingTransactions"] = json::array();
    {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& tx : pendingTransactions) {
            j["pendingTransactions"].push_back(tx.toJson());
        }
    }
    j["difficulty"] = difficulty;
    return j;
}

void Blockchain::fromJson(const json& j) {
    chain.clear();
    for (const auto& blockJson : j.at("chain")) {
        Block block;
        block.fromJson(blockJson);
        chain.push_back(block);
    }
    {
        std::lock_guard<std::mutex> lock(mtx);
        pendingTransactions.clear();
        for (const auto& txJson : j.at("pendingTransactions")) {
            Transaction tx;
            tx.fromJson(txJson);
            pendingTransactions.push_back(tx);
        }
    }
    difficulty = j.at("difficulty").get<int>();
}

bool Blockchain::isChainValid() const {
    if (chain.empty())
        return false;
    // Verify genesis block.
    if (chain[0].prevHash != "0") {
        std::cerr << "Genesis block has invalid previous hash." << std::endl;
        return false;
    }
    // Verify subsequent blocks.
    for (size_t i = 1; i < chain.size(); ++i) {
        const Block& currentBlock = chain[i];
        const Block& previousBlock = chain[i - 1];
        if (currentBlock.prevHash != previousBlock.blockHash) {
            std::cerr << "Chain broken between blocks " << i - 1 << " and " << i << std::endl;
            return false;
        }
        if (currentBlock.blockHash != currentBlock.generateHash()) {
            std::cerr << "Block " << i << " has an invalid hash." << std::endl;
            return false;
        }
    }
    return true;
}

bool Blockchain::addBlock(const Block& block) {
    if (chain.empty()) {
        std::cerr << "Chain is empty. Cannot add block." << std::endl;
        return false;
    }
    if (block.prevHash != chain.back().blockHash) {
        std::cerr << "Block's previous hash does not match the last block's hash." << std::endl;
        return false;
    }
    if (block.blockHash != block.generateHash()) {
        std::cerr << "Block hash is invalid." << std::endl;
        return false;
    }
    chain.push_back(block);
    return true;
}

bool Blockchain::addTransaction(const Transaction& tx) {
    // Check for duplicate transactions.
    {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& pendingTx : pendingTransactions) {
            if (pendingTx.voterId == tx.voterId &&
                pendingTx.candidateId == tx.candidateId &&
                pendingTx.nonce == tx.nonce &&
                pendingTx.signature == tx.signature) {
                std::cerr << "Duplicate transaction detected. Transaction not added." << std::endl;
                return false;
            }
        }
        pendingTransactions.push_back(tx);
    }
    return true;
}

bool Blockchain::replaceChain(const Blockchain& newChain) {
    if (newChain.chain.size() > chain.size() && newChain.isChainValid()) {
        chain = newChain.chain;
        {
            std::lock_guard<std::mutex> lock(mtx);
            pendingTransactions = newChain.pendingTransactions;
        }
        difficulty = newChain.difficulty;
        return true;
    }
    return false;
}

std::unordered_map<std::string, int> Blockchain::tallyVotes() const {
    std::unordered_map<std::string, int> voteCount;
    // Skip genesis block if desired.
    for (size_t i = 1; i < chain.size(); ++i) {
        const Block& block = chain[i];
        for (const auto& tx : block.transactions) {
            voteCount[tx.candidateId]++;
        }
    }
    return voteCount;
}

int Blockchain::getPendingTransactionCount() const {
    std::lock_guard<std::mutex> lock(mtx);
    return static_cast<int>(pendingTransactions.size());
}

void Blockchain::clearPendingTransactions(const Block& block) {
    std::lock_guard<std::mutex> lock(mtx);
    // Remove only those transactions that are included in the new block.
    pendingTransactions.erase(
        std::remove_if(
            pendingTransactions.begin(),
            pendingTransactions.end(),
            [&block](const Transaction& pendingTx) -> bool {
                for (const auto& blockTx : block.transactions) {
                    if (pendingTx.voterId == blockTx.voterId &&
                        pendingTx.candidateId == blockTx.candidateId &&
                        pendingTx.nonce == blockTx.nonce &&
                        pendingTx.signature == blockTx.signature) {
                        return true;  // Mark for removal.
                    }
                }
                return false;
            }
        ),
        pendingTransactions.end()
    );
}

bool Blockchain::verifyBlock(const Block& block) const {
    if (chain.empty()) {
        return false;
    }
    // Verify that the block's previous hash matches the hash of the last block.
    const Block& lastBlock = chain.back();
    if (block.prevHash != lastBlock.blockHash) {
        std::cerr << "verifyBlock: Block's previous hash (" << block.prevHash
            << ") does not match last block's hash (" << lastBlock.blockHash << ")." << std::endl;
        return false;
    }
    // Verify that the block's stored hash equals the generated hash.
    if (block.blockHash != block.generateHash()) {
        std::cerr << "verifyBlock: Block hash is invalid." << std::endl;
        return false;
    }
    return true;
}
