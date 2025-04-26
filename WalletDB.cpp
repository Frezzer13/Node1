#include "WalletDB.h"
#include <sqlite3.h>
#include <iostream>

bool WalletDB::walletExists(const std::string& voterId, std::string* publicKeyOut) {
    sqlite3* db;
    int rc = sqlite3_open("wallets.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    const char* sql = "SELECT publicKey FROM wallets WHERE voterId = ?;";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }
    sqlite3_bind_text(stmt, 1, voterId.c_str(), -1, SQLITE_TRANSIENT);
    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = true;
        if (publicKeyOut) {
            const unsigned char* pk = sqlite3_column_text(stmt, 0);
            *publicKeyOut = pk ? reinterpret_cast<const char*>(pk) : "";
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return exists;
}
