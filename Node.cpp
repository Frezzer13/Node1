#include "Node.h"
#include "WalletDB.h"        // Вспомогательная функция для запросов к базе данных кошельков
#include "KeyUtils.h"
#include <iostream>
#include <algorithm>
#include <boost/asio.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <boost/asio/ip/address_v4.hpp>
#include <regex>
#include <algorithm> // для std::remove_if

// Helper function to extract Base64-encoded content from PEM.
std::string extractBase64(const std::string& pem) {
    std::regex base64Regex("-----BEGIN [^-]+-----\\s*([A-Za-z0-9+/=\\s]+)\\s*-----END [^-]+-----");
    std::smatch match;
    if (std::regex_search(pem, match, base64Regex) && match.size() >= 2) {
        std::string base64 = match[1].str();
        base64.erase(std::remove_if(base64.begin(), base64.end(), ::isspace), base64.end());
        return base64;
    }
    return pem;
}

// Session Implementation

Session::Session(tcp::socket socket, Node* node)
    : socket_(std::move(socket)), node_(node)
{
}

void Session::start() {
    doRead();
}

void Session::doRead() {
    auto self(shared_from_this());
    boost::asio::async_read_until(socket_, streambuf_, "\n",
        [this, self](boost::system::error_code ec, std::size_t /*length*/) {
            if (!ec) {
                std::istream is(&streambuf_);
                std::string line;
                std::getline(is, line);
                if (!line.empty()) {
                    try {
                        nlohmann::json message = nlohmann::json::parse(line);
                        std::cout << "Received message: " << std::endl;
                        node_->handleMessage(message, self);
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
                    }
                }
                doRead();
            }
            else {
                std::cerr << "Read error: " << ec.message() << std::endl;
            }
        });
}

void Session::sendMessage(const std::string& msg) {
    doWrite(msg);
}

void Session::doWrite(const std::string& msg) {
    auto self(shared_from_this());
    auto fullMsg = std::make_shared<std::string>(msg + "\n");
    boost::asio::async_write(socket_, boost::asio::buffer(*fullMsg),
        [this, self, fullMsg](boost::system::error_code ec, std::size_t /*length*/) {
            if (ec) {
                std::cerr << "Write error: " << ec.message() << std::endl;
            }
        });
}

// Node Implementation

// Конструктор, принимающий IP-адрес и порт.
Node::Node(const std::string& ip, short port)
    : io_context_(),
    acceptor_(io_context_, tcp::endpoint(boost::asio::ip::make_address(ip), port))
{
    doAccept();
}

void Node::run() {
    try {
        io_context_.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Node run error: " << e.what() << std::endl;
    }
}

void Node::doAccept() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            std::cout << "Accepted new connection." << std::endl;
            auto session = std::make_shared<Session>(std::move(socket), this);
            sessions_.push_back(session);
            session->start();
        }
        else {
            std::cerr << "Accept error: " << ec.message() << std::endl;
        }
        doAccept();
        });
}

void Node::connectToPeer(const std::string& host, const std::string& port) {
    tcp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(host, port);
    auto socket = std::make_shared<tcp::socket>(io_context_);
    boost::asio::async_connect(*socket, endpoints,
        [this, socket](boost::system::error_code ec, tcp::endpoint) {
            if (!ec) {
                std::cout << "Connected to peer." << std::endl;
                auto session = std::make_shared<Session>(std::move(*socket), this);
                sessions_.push_back(session);
                session->start();
            }
            else {
                std::cerr << "Connection failed: " << ec.message() << std::endl;
            }
        });
}

void Node::broadcastMessage(const nlohmann::json& message, std::shared_ptr<Session> exclude) {
    std::string msgStr = message.dump();
    for (auto& session : sessions_) {
        if (session != exclude) {
            session->sendMessage(msgStr);
        }
    }
}

void Node::handleMessage(const nlohmann::json& message, std::shared_ptr<Session> sender) {
    if (!message.contains("type") || !message.contains("data")) {
        std::cerr << "Invalid message format." << std::endl;
        return;
    }
    std::string type = message["type"];
    if (type == "TRANSACTION") {
        try {
            Transaction tx;
            tx.fromJson(message["data"]);
            std::string voterId = tx.voterId;
            std::string txPublicKey = tx.publicKey;
            std::string storedPubKey;
            if (!WalletDB::walletExists(voterId, &storedPubKey)) {
                std::cerr << "Wallet for voterId " << voterId << " not found in DB. Transaction rejected." << std::endl;
                return;
            }
            if (extractBase64(storedPubKey) != extractBase64(txPublicKey)) {
                std::cerr << "Public key mismatch for voterId " << voterId << ". Transaction rejected." << std::endl;
                return;
            }
            EVP_PKEY* pubKey = loadPublicKey(storedPubKey);
            bool validSignature = tx.verify(pubKey);
            EVP_PKEY_free(pubKey);
            if (!validSignature) {
                std::cerr << "Transaction signature invalid for voterId " << voterId << "." << std::endl;
                return;
            }
            std::cout << "Received transaction from " << voterId << std::endl;
            if (blockchain_.addTransaction(tx)) {
                std::cout << "Transaction added to pending transactions." << std::endl;
                broadcastMessage(message, sender);
            }
            else {
                std::cout << "Transaction rejected (duplicate or invalid)." << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error processing TRANSACTION message: " << e.what() << std::endl;
        }
    }
    else if (type == "BLOCK") {
        try {
            Block newBlock;
            newBlock.fromJson(message["data"]);
            std::cout << "Received block: " << std::endl;
            if (blockchain_.verifyBlock(newBlock)) {
                if (blockchain_.addBlock(newBlock)) {
                    std::cout << "Block added to blockchain." << std::endl;
                    blockchain_.clearPendingTransactions(newBlock);
                    broadcastMessage(message, sender);
                }
                else {
                    std::cout << "Block rejected during addBlock." << std::endl;
                }
            }
            else {
                std::cout << "Block verification failed." << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error processing BLOCK message: " << e.what() << std::endl;
        }
    }
    else if (type == "REQUEST_CHAIN") {
        nlohmann::json response;
        response["type"] = "CHAIN";
        response["data"] = blockchain_.toJson();
        sender->sendMessage(response.dump());
    }
    else if (type == "CHAIN") {
        try {
            Blockchain receivedChain;
            receivedChain.fromJson(message["data"]);
            if (blockchain_.replaceChain(receivedChain)) {
                std::cout << "Local blockchain updated with received chain." << std::endl;
            }
            else {
                std::cout << "Received blockchain was not longer or not valid." << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error processing CHAIN message: " << e.what() << std::endl;
        }
    }
    else {
        std::cerr << "Unknown message type: " << type << std::endl;
    }
}

void Node::minePendingTransactions() {
    std::vector<Transaction> snapshot = blockchain_.pendingTransactions;
    if (snapshot.empty()) {
        std::cout << "No pending transactions to mine." << std::endl;
        return;
    }
    Block newBlock(snapshot, blockchain_.chain.back().blockHash, blockchain_.difficulty);
    if (blockchain_.addBlock(newBlock)) {
        std::cout << "New block mined and added to blockchain: " << newBlock.blockHash << std::endl;
        blockchain_.clearPendingTransactions(newBlock);
        nlohmann::json blockMessage;
        blockMessage["type"] = "BLOCK";
        blockMessage["data"] = newBlock.toJson();
        broadcastMessage(blockMessage);
    }
    else {
        std::cout << "Failed to mine block." << std::endl;
    }
}

void Node::printVoteTally() {
    auto tally = blockchain_.tallyVotes();
    std::cout << "Vote Tally:" << std::endl;
    for (const auto& pair : tally) {
        std::cout << "Candidate: " << pair.first << " - Votes: " << pair.second << std::endl;
    }
}

void Node::addLocalTransaction(const nlohmann::json& message) {
    try {
        Transaction tx;
        tx.fromJson(message["data"]);
        if (blockchain_.addTransaction(tx)) {
            std::cout << "Local transaction added to pending transactions." << std::endl;
        }
        else {
            std::cout << "Transaction rejected (duplicate or invalid)." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error adding local transaction: " << e.what() << std::endl;
    }
}

int Node::getPendingTransactionCount() const {
    return static_cast<int>(blockchain_.pendingTransactions.size());
}

void Node::printBlockchainJson() const {
    std::cout << blockchain_.toJson().dump(4) << std::endl;
}
