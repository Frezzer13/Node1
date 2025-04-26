#ifndef WALLET_DB_H
#define WALLET_DB_H

#include <string>

class WalletDB {
public:
    static bool walletExists(const std::string& voterId, std::string* publicKeyOut = nullptr);
};

#endif // WALLET_DB_H
