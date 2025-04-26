#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include "Block.h"
#include "Transaction.h"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <mutex>

class Blockchain {
public:
    // The chain of blocks.
    std::vector<Block> chain;
    // The pending (unconfirmed) transactions.
    std::vector<Transaction> pendingTransactions;
    int difficulty;  // Current mining difficulty.

    // Constructor.
    Blockchain();

    // Serialize the blockchain to JSON.
    nlohmann::json toJson() const;

    // Deserialize the blockchain from JSON.
    void fromJson(const nlohmann::json& j);

    // Add a block to the chain if it is valid.
    bool addBlock(const Block& block);

    // Add a transaction to the pending transactions.
    bool addTransaction(const Transaction& tx);

    // Replace the local chain with a new one if the new one is longer and valid.
    bool replaceChain(const Blockchain& newChain);

    // Validate the entire chain.
    bool isChainValid() const;

    // Tally votes by candidate.
    std::unordered_map<std::string, int> tallyVotes() const;

    // Return the count of pending transactions in a thread-safe manner.
    int getPendingTransactionCount() const;

    // Remove from pendingTransactions only those transactions that are included in the given block.
    void clearPendingTransactions(const Block& block);

    // Verify a block by checking its previous hash and its own hash.
    bool verifyBlock(const Block& block) const;

private:
    mutable std::mutex mtx;  // Mutex to synchronize access to pendingTransactions.
};

#endif // BLOCKCHAIN_H
