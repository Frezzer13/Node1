#ifndef NODE_H
#define NODE_H

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <string>
#include "nlohmann/json.hpp"
#include "Blockchain.h"  // ������������ ���� ������ Blockchain

using boost::asio::ip::tcp;
using json = nlohmann::json;

class Node; // Forward declaration (���� ����� ��� Session)

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, Node* node);
    void start();
    void sendMessage(const std::string& msg);
private:
    void doRead();
    void doWrite(const std::string& msg);
    tcp::socket socket_;
    Node* node_;
    boost::asio::streambuf streambuf_;
};

class Node {
public:
    // �����������, ����������� IP-����� � ����.
    Node(const std::string& ip, short port);
    void run();
    void connectToPeer(const std::string& host, const std::string& port);
    void broadcastMessage(const json& message, std::shared_ptr<Session> exclude = nullptr);
    void handleMessage(const json& message, std::shared_ptr<Session> sender);
    void minePendingTransactions();
    void printVoteTally();
    void addLocalTransaction(const json& message);
    int getPendingTransactionCount() const;
    void printBlockchainJson() const; // �������������� ������� ��� ������ ���������

private:
    void doAccept();
    boost::asio::io_context io_context_;
    tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<Session>> sessions_;
    Blockchain blockchain_;
};

#endif // NODE_H
