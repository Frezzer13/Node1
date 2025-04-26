// main_nodeA.cpp
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include "sqlite3.h"
#include "Node.h"
#include "WalletDB.h"     // For loading wallet data from the database
#include "KeyUtils.h"     // Contains inline loadPrivateKey() and loadPublicKey()
#include "Vote.h"
#include "Transaction.h"
#include "nlohmann/json.hpp"

#pragma comment(lib, "Ws2_32.lib")
using json = nlohmann::json;

// Structure to hold wallet data loaded from the DB.
struct WalletData {
    std::string voterId;
    std::string publicKey;
    std::string privateKey;
};

// Load all wallets from the database.
std::vector<WalletData> loadAllWallets(const std::string& dbPath = "wallets.db") {
    std::vector<WalletData> wallets;
    sqlite3* db;
    int rc = sqlite3_open(dbPath.c_str(), &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return wallets;
    }
    const char* sql = "SELECT voterId, publicKey, privateKey FROM wallets;";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return wallets;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WalletData wd;
        wd.voterId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        wd.publicKey = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        wd.privateKey = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        wallets.push_back(wd);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return wallets;
}

// Filter wallets for Node A: voters 1 to 50.
std::vector<WalletData> filterWalletsForNodeA(const std::vector<WalletData>& allWallets) {
    std::vector<WalletData> result;
    for (const auto& wd : allWallets) {
        if (wd.voterId.substr(0, 5) == "voter") {
            try {
                int num = std::stoi(wd.voterId.substr(5));
                if (num >= 1 && num <= 50)
                    result.push_back(wd);
            }
            catch (...) {
                // Skip invalid formats.
            }
        }
    }
    return result;
}

// Helper function to convert a Vote into a Transaction.
Transaction voteToTransaction(const Vote& vote) {
    return Transaction(vote);  // Uses the conversion constructor.
}

// Auto-generation thread function for Node A that generates exactly 'limit' transactions.
void autoGenerateTransactions(Node& node, const std::vector<WalletData>& wallets, int limit) {
    int count = 0;
    const char* candidates[3] = { "CandidateA", "CandidateB", "CandidateC" };
    while (count < limit) {
        int sleepTime = 3 + rand() % 4; // Random interval between 3 and 6 seconds.
        std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
        // Select a random wallet from the list.
        int index = rand() % wallets.size();
        WalletData wd = wallets[index];
        // Randomly choose a candidate.
        std::string candidate = candidates[rand() % 3];
        try {
            int nonce = rand();
            Vote vote(wd.voterId, candidate, nonce);
            EVP_PKEY* privKey = loadPrivateKey(wd.privateKey);
            vote.sign(privKey);
            EVP_PKEY_free(privKey);
            vote.publicKey = wd.publicKey;
            Transaction tx = voteToTransaction(vote);
            json message;
            message["type"] = "TRANSACTION";
            message["data"] = tx.toJson();
            std::cout << "Auto-generated transaction from " << wd.voterId
                << " for " << candidate << std::endl;
            node.addLocalTransaction(message);
            node.broadcastMessage(message);
            count++;
            // Note: Do NOT automatically trigger final mining here.
            if (node.getPendingTransactionCount() >= 10) {
                std::cout << "Pending transaction threshold reached. Triggering mining..." << std::endl;
                node.minePendingTransactions();
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "Error generating transaction: " << ex.what() << std::endl;
        }
    }
    std::cout << "Auto-generation thread reached limit of " << limit << " transactions and is stopping." << std::endl;
}

int main() {
    srand(static_cast<unsigned int>(time(nullptr)));
    try {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed." << std::endl;
            return 1;
        }
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);
        std::cout << "Console is set to UTF-8." << std::endl;

        // Load all wallets from DB and filter for Node A (voter1 to voter50).
        std::vector<WalletData> allWallets = loadAllWallets("wallets.db");
        std::vector<WalletData> nodeAWallets = filterWalletsForNodeA(allWallets);
        if (nodeAWallets.empty()) {
            std::cerr << "No wallets found for Node A." << std::endl;
            return 1;
        }
        std::cout << "Node A loaded " << nodeAWallets.size() << " wallets." << std::endl;

        // Create a Node listening on port 12345.
        Node node("127.0.0.1",12345);

        // Run the node's event loop in a separate thread.
        std::thread nodeThread([&node]() {
            node.run();
            });

        // Start auto-generation of exactly 25 transactions.
        const int txLimit = 25;
        std::thread autoGenThread(autoGenerateTransactions, std::ref(node), nodeAWallets, txLimit);

        // Interactive command loop.
        std::cout << "Enter command:" << std::endl;
        std::cout << "  b - broadcast manual transaction (vote)" << std::endl;
        std::cout << "  m - mine pending transactions" << std::endl;
        std::cout << "  t - print vote tally" << std::endl;
        std::cout << "  q - quit" << std::endl;
        while (true) {
            std::string command;
            std::getline(std::cin, command);
            if (command == "b") {
                const char* candidates[3] = { "CandidateA", "CandidateB", "CandidateC" };
                std::string candidate = candidates[rand() % 3];
                try {
                    int nonce = rand();
                    int index = rand() % nodeAWallets.size();
                    WalletData wd = nodeAWallets[index];
                    Vote vote(wd.voterId, candidate, nonce);
                    EVP_PKEY* privKey = loadPrivateKey(wd.privateKey);
                    vote.sign(privKey);
                    EVP_PKEY_free(privKey);
                    vote.publicKey = wd.publicKey;
                    EVP_PKEY* pubKey = loadPublicKey(wd.publicKey);
                    if (!vote.verify(pubKey)) {
                        std::cerr << "Manual vote signature verification failed." << std::endl;
                        EVP_PKEY_free(pubKey);
                        continue;
                    }
                    EVP_PKEY_free(pubKey);
                    Transaction tx = voteToTransaction(vote);
                    json message;
                    message["type"] = "TRANSACTION";
                    message["data"] = tx.toJson();
                    std::cout << "Broadcasting manual transaction for " << candidate
                        << " from " << wd.voterId << std::endl;
                    node.addLocalTransaction(message);
                    node.broadcastMessage(message);
                }
                catch (const std::exception& ex) {
                    std::cerr << "Error creating manual vote: " << ex.what() << std::endl;
                }
            }
            else if (command == "m") {
                std::cout << "Mining pending transactions..." << std::endl;
                node.minePendingTransactions();
            }
            else if (command == "t") {
                node.printVoteTally();
            }
            else if (command == "q") {
                std::cout << "Quitting..." << std::endl;
                break;
            }
            else if (command == "j") {
                // New command: Print the entire blockchain in JSON format.
                node.printBlockchainJson();
            }
            else {
                std::cout << "Unknown command. Use 'b', 'm', 't', or 'q'." << std::endl;
            }
        }

        // Wait for threads to finish.
        autoGenThread.join();
        nodeThread.join();
        WSACleanup();
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}