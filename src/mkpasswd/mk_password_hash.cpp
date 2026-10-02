// Argon2id password hashing with libsodium, including migration from legacy MD5 hashes.
//
// Install:  sudo apt install libsodium-dev      (Debian/Ubuntu)
//           brew install libsodium              (macOS)
//           vcpkg install libsodium             (Windows)
// Build:    g++ -std=c++17 -O2 mk_password_hash.cpp -o mk_password_hash -lsodium

#include <sodium.h>

#include <iostream>
#include <stdexcept>
#include <string>

// Tune these to your server. MODERATE = ~256 MiB RAM, ~0.7 s on a typical CPU.
// INTERACTIVE = 64 MiB, ~0.1 s (the OWASP-style minimum is roughly this or higher).
// On a small/embedded box, use INTERACTIVE or lower the values yourself.
constexpr unsigned long long OPS_LIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr size_t MEM_LIMIT = crypto_pwhash_MEMLIMIT_MODERATE;

// Returns a self-contained string like "$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>"
// Store this string in a single database column.
std::string hash_password(const std::string& password) {
    char out[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str_alg(out, password.c_str(), password.size(),
                              OPS_LIMIT, MEM_LIMIT,
                              crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("password hashing failed (out of memory?)");
    }
    return std::string(out);
}

// Constant-time verification.
bool verify_password(const std::string& stored_hash, const std::string& password) {
    return crypto_pwhash_str_verify(stored_hash.c_str(), password.c_str(),
                                    password.size()) == 0;
}

// True if the stored hash uses weaker parameters than the current settings
// (or a different algorithm) and should be re-hashed at next successful login.
bool needs_rehash(const std::string& stored_hash) {
    return crypto_pwhash_str_needs_rehash(stored_hash.c_str(), OPS_LIMIT, MEM_LIMIT) != 0;
}

// ---------------------------------------------------------------------------
// Migration from MD5 without forcing a password reset.
//
// Step 1 (one-off script): for every user, store
//     hash_password(legacy_md5_hex)   and set legacy_wrapped = true
// Step 2 (at login): see login() below.
// ---------------------------------------------------------------------------

struct UserRecord {
    std::string hash;
    bool legacy_wrapped;  // true = hash is argon2id(md5_hex_of_password)
};

// Provide your own MD5 hex function only for the legacy path
// (e.g. the one your server already uses).
std::string md5_hex(const std::string& s);

bool login(UserRecord& user, const std::string& password) {
    if (user.legacy_wrapped) {
        if (!verify_password(user.hash, md5_hex(password))) return false;
        // Success: upgrade to a plain Argon2id hash of the real password.
        user.hash = hash_password(password);
        user.legacy_wrapped = false;
        // ...persist user to the database here...
        return true;
    }

    if (!verify_password(user.hash, password)) return false;

    if (needs_rehash(user.hash)) {
        user.hash = hash_password(password);
        // ...persist user to the database here...
    }
    return true;
}

#ifndef NO_MAIN
// Placeholder so the demo links; replace with your real legacy MD5 function.
std::string md5_hex(const std::string&) { return std::string(); }

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <password>\n";
        return 2;
    }

    if (sodium_init() < 0) {  // call once at startup
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    try {
        const std::string stored = hash_password(argv[1]);
        std::cout << stored << '\n';
    }
    catch (const std::exception& error) {
        std::cerr << "password hashing failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
#endif
