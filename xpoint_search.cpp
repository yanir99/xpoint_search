#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <cstring>
#include <cctype>
#include <stdexcept>

// OpenSSL includes for secp256k1
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>  // For NID_secp256k1
#include <openssl/evp.h>      // For newer OpenSSL APIs

// Suppress deprecation warnings for OpenSSL 3.0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// String helpers
static inline void trim_left(std::string& s) {
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    s.erase(0, i);
}
static inline void trim_right(std::string& s) {
    if (s.empty()) return;
    size_t i = s.size();
    while (i > 0 && std::isspace(static_cast<unsigned char>(s[i-1]))) --i;
    s.erase(i);
}
static inline void trim(std::string& s) { trim_right(s); trim_left(s); }

// Helper function to convert hex string to BIGNUM
BIGNUM* hex_to_bignum(const std::string& hex_str) {
    BIGNUM* bn = BN_new();
    if (!bn) return nullptr;

    std::string clean_hex = hex_str;
    // Remove 0x prefix if present
    if (clean_hex.length() >= 2 &&
        (clean_hex.substr(0, 2) == "0x" || clean_hex.substr(0, 2) == "0X")) {
        clean_hex = clean_hex.substr(2);
    }

    if (BN_hex2bn(&bn, clean_hex.c_str()) == 0) {
        BN_free(bn);
        return nullptr;
    }

    return bn;
}

// BloomFilter
class BloomFilter {
private:
    std::vector<uint8_t> bit_array;
    size_t size;
    int hash_count;

    std::vector<size_t> get_hashes(const std::string& item) const {
        std::vector<size_t> hashes;
        if (size == 0) return hashes;
        for (int i = 0; i < hash_count; ++i) {
            std::string data = item + std::to_string(i);
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

            size_t hash_val = 0;
            for (int j = 0; j < 8; ++j) {
                hash_val = (hash_val << 8) | hash[j];
            }
            hashes.push_back(hash_val % size);
        }
        return hashes;
    }

public:
    BloomFilter(size_t n_items, double false_positive_rate = 0.001) {
        if (n_items == 0) {
            size = 8;
            hash_count = 1;
        } else {
            double m = -(n_items * std::log(false_positive_rate)) / (std::log(2) * std::log(2));
            size = static_cast<size_t>(std::max(8.0, m));
            hash_count = std::max(1, static_cast<int>((size / static_cast<double>(n_items)) * std::log(2)));
        }
        bit_array.resize(size, 0);
    }

    BloomFilter(size_t n_items, size_t fixed_size) {
        size = std::max<size_t>(8, fixed_size);
        hash_count = std::max(1, static_cast<int>((size / std::max(1.0, static_cast<double>(n_items))) * std::log(2)));
        bit_array.resize(size, 0);
    }

    void add(const std::string& item) {
        auto hashes = get_hashes(item);
        for (size_t idx : hashes) {
            bit_array[idx] = 1;
        }
    }

    bool contains(const std::string& item) const {
        auto hashes = get_hashes(item);
        for (size_t idx : hashes) {
            if (idx >= bit_array.size() || !bit_array[idx]) return false;
        }
        return true;
    }
};

class SECP256K1 {
private:
    EC_GROUP* group;
    EC_POINT* generator;
    BIGNUM* order;

public:
    SECP256K1() {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) {
            throw std::runtime_error("Failed to create secp256k1 group");
        }

        generator = EC_POINT_new(group);
        if (!generator) {
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create generator point");
        }

        order = BN_new();
        if (!order) {
            EC_POINT_free(generator);
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create order");
        }

        if (!EC_GROUP_get_order(group, order, nullptr)) {
            BN_free(order);
            EC_POINT_free(generator);
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to get group order");
        }

        const EC_POINT* gen = EC_GROUP_get0_generator(group);
        if (!gen || !EC_POINT_copy(generator, gen)) {
            BN_free(order);
            EC_POINT_free(generator);
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to copy generator");
        }
    }

    ~SECP256K1() {
        if (group) EC_GROUP_free(group);
        if (generator) EC_POINT_free(generator);
        if (order) BN_free(order);
    }

    std::string compress_point(const EC_POINT* point, BN_CTX* ctx) const {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();

        if (!x || !y) {
            if (x) BN_free(x);
            if (y) BN_free(y);
            return "";
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
            BN_free(x);
            BN_free(y);
            return "";
        }

        std::string result = BN_is_odd(y) ? "03" : "02";

        char* x_hex = BN_bn2hex(x);
        if (!x_hex) {
            BN_free(x);
            BN_free(y);
            return "";
        }

        std::string x_str(x_hex);
        OPENSSL_free(x_hex);

        // Convert to lowercase and pad to 64 characters
        std::transform(x_str.begin(), x_str.end(), x_str.begin(), ::tolower);
        while (x_str.length() < 64) {
            x_str = "0" + x_str;
        }

        result += x_str;

        BN_free(x);
        BN_free(y);

        return result;
    }

    EC_POINT* multiply(const BIGNUM* scalar, BN_CTX* ctx) const {
        EC_POINT* result = EC_POINT_new(group);
        if (!result) return nullptr;

        if (!EC_POINT_mul(group, result, scalar, nullptr, nullptr, ctx)) {
            EC_POINT_free(result);
            return nullptr;
        }

        return result;
    }

    EC_GROUP* get_group() const { return group; }
    BIGNUM* get_order() const { return order; }
};

struct SearchResult {
    bool found;
    std::string r_hex;
    std::string offset_dec;       // store decimal offset as string
    std::string pub_compressed;
    std::string private_key;
};

class XPointSearcher {
private:
    // Map compressed pubkey -> decimal offset string (may be huge)
    std::unordered_map<std::string, std::string> table;
    std::unique_ptr<BloomFilter> bloom;
    SECP256K1 secp;
    std::atomic<uint64_t> processed{0};
    std::atomic<bool> found_flag{false};
    std::atomic<bool> done_flag{false};
    SearchResult result;
    std::mutex result_mutex;

    static bool parse_offset_to_bignum(const std::string& dec_str, BIGNUM** out) {
        std::string s = dec_str;
        trim(s);
        if (s.empty()) return false;

        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, s.c_str()) == 0) {
            if (bn) BN_free(bn);
            return false;
        }
        *out = bn;
        return true;
    }

    static bool parse_offset_abs_sign(const std::string& dec_str, bool& is_negative, std::string& abs_dec) {
        std::string s = dec_str;
        trim(s);
        if (s.empty()) return false;
        is_negative = false;
        size_t pos = 0;
        if (s[0] == '+' || s[0] == '-') {
            is_negative = (s[0] == '-');
            pos = 1;
        }
        abs_dec = s.substr(pos);
        size_t nz = 0;
        while (nz < abs_dec.size() && abs_dec[nz] == '0') ++nz;
        abs_dec = (nz == abs_dec.size()) ? "0" : abs_dec.substr(nz);
        return true;
    }

    static bool dec_to_bignum_positive(const std::string& abs_dec, BIGNUM** out) {
        if (abs_dec.empty()) return false;
        BIGNUM* bn = nullptr;
        if (BN_dec2bn(&bn, abs_dec.c_str()) == 0) {
            if (bn) BN_free(bn);
            return false;
        }
        if (BN_is_negative(bn)) {
            BN_free(bn);
            return false;
        }
        *out = bn;
        return true;
    }

    bool load_table_chunked(const std::string& filename, bool use_bloom,
                            double bloom_fpr, size_t bloom_size) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open table file: " << filename << std::endl;
            return false;
        }

        std::string line;
        size_t line_count = 0;
        size_t valid_offsets = 0;

        std::cout << "Loading table..." << std::endl;
        while (std::getline(file, line)) {
            trim(line);
            if (line.empty()) continue;

            size_t hash_pos = line.find('#');
            if (hash_pos == std::string::npos) continue;

            std::string hex_part = line.substr(0, hash_pos);
            std::string offset_str = line.substr(hash_pos + 1);

            trim(hex_part);
            trim(offset_str);

            if (hex_part.size() < 66) continue; // compressed key len
            if (!(hex_part.rfind("02", 0) == 0 || hex_part.rfind("03", 0) == 0)) continue;

            // Keep only first token in case of packed lines
            {
                std::istringstream iss(hex_part);
                std::string first;
                iss >> first;
                hex_part = first;
            }

            if (hex_part.size() != 66) continue;

            // Validate offset parses to BN
            BIGNUM* test = nullptr;
            if (!parse_offset_to_bignum(offset_str, &test)) continue;
            BN_free(test);

            table[hex_part] = offset_str;
            ++valid_offsets;
            ++line_count;

            if (line_count % 1000000 == 0) {
                std::cout << "Loaded " << line_count << " entries..." << std::endl;
            }
        }

        if (valid_offsets == 0) {
            std::cerr << "Error: No valid offsets found in table." << std::endl;
            return false;
        }

        std::cout << "Loaded " << table.size() << " public keys." << std::endl;

        if (use_bloom) {
            std::cout << "Creating Bloom filter..." << std::endl;
            if (bloom_size > 0) {
                bloom = std::make_unique<BloomFilter>(table.size(), bloom_size);
            } else {
                bloom = std::make_unique<BloomFilter>(table.size(), bloom_fpr);
            }

            size_t count = 0;
            for (const auto& pair : table) {
                bloom->add(pair.first);
                count++;
                if (count % 1000000 == 0) {
                    std::cout << "Added " << count << " items to Bloom filter..." << std::endl;
                }
            }
            std::cout << "Bloom filter created." << std::endl;
        }

        return true;
    }

    void worker_thread_bignum(const BIGNUM* start_bn, const BIGNUM* end_bn,
                              uint64_t max_iterations, int /*thread_id*/) {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) return;

        BIGNUM* r_bn = BN_new();
        BIGNUM* one = BN_new();
        if (!r_bn || !one) {
            if (r_bn) BN_free(r_bn);
            if (one) BN_free(one);
            BN_CTX_free(ctx);
            return;
        }

        BN_copy(r_bn, start_bn);
        BN_set_word(one, 1);

        uint64_t iterations = 0;
        while (BN_cmp(r_bn, end_bn) <= 0 && !found_flag.load() && iterations < max_iterations) {
            EC_POINT* point = secp.multiply(r_bn, ctx);
            if (!point) {
                BN_add(r_bn, r_bn, one);
                iterations++;
                continue;
            }

            std::string comp_hex = secp.compress_point(point, ctx);

            if (comp_hex.size() != 66) {
                EC_POINT_free(point);
                BN_add(r_bn, r_bn, one);
                iterations++;
                continue;
            }

            if (bloom && !bloom->contains(comp_hex)) {
                EC_POINT_free(point);
                BN_add(r_bn, r_bn, one);
                iterations++;
                continue;
            }

            auto it = table.find(comp_hex);
            if (it != table.end()) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!found_flag.load()) {
                    found_flag.store(true);
                    result.found = true;

                    char* r_hex_str = BN_bn2hex(r_bn);
                    if (r_hex_str) {
                        result.r_hex = std::string(r_hex_str);
                        OPENSSL_free(r_hex_str);
                    }

                    result.pub_compressed = comp_hex;
                    result.offset_dec = it->second; // decimal string

                    bool is_neg = false;
                    std::string abs_dec;
                    if (parse_offset_abs_sign(it->second, is_neg, abs_dec)) {
                        BIGNUM* priv_bn = BN_new();
                        BIGNUM* off_abs_bn = nullptr;
                        if (priv_bn && dec_to_bignum_positive(abs_dec, &off_abs_bn)) {
                            if (!is_neg) {
                                // r - offset mod n
                                BN_mod_sub(priv_bn, r_bn, off_abs_bn, secp.get_order(), ctx);
                            } else {
                                // r + |offset| mod n
                                BN_mod_add(priv_bn, r_bn, off_abs_bn, secp.get_order(), ctx);
                            }

                            char* priv_hex = BN_bn2hex(priv_bn);
                            if (priv_hex) {
                                result.private_key = std::string(priv_hex);
                                OPENSSL_free(priv_hex);

                                std::transform(result.private_key.begin(), result.private_key.end(),
                                               result.private_key.begin(), ::tolower);
                                while (result.private_key.length() < 64) {
                                    result.private_key = "0" + result.private_key;
                                }
                            }
                        }
                        if (off_abs_bn) BN_free(off_abs_bn);
                        if (priv_bn) BN_free(priv_bn);
                    }
                }
            }

            EC_POINT_free(point);
            processed.fetch_add(1);
            BN_add(r_bn, r_bn, one);
            iterations++;
        }

        BN_free(r_bn);
        BN_free(one);
        BN_CTX_free(ctx);
    }

public:
    bool load_table(const std::string& filename, bool use_bloom = false,
                    double bloom_fpr = 0.001, size_t bloom_size = 0) {
        return load_table_chunked(filename, use_bloom, bloom_fpr, bloom_size);
    }

    SearchResult search_bignum(const std::string& start_hex, const std::string& end_hex,
                               int num_threads = std::thread::hardware_concurrency(),
                               uint64_t max_per_thread = 1000000) {

        result = SearchResult{false, "", "", "", ""};
        found_flag.store(false);
        done_flag.store(false);
        processed.store(0);

        BIGNUM* start_bn = hex_to_bignum(start_hex);
        BIGNUM* end_bn = hex_to_bignum(end_hex);

        if (!start_bn || !end_bn) {
            std::cerr << "Error: Invalid hex range values" << std::endl;
            if (start_bn) BN_free(start_bn);
            if (end_bn) BN_free(end_bn);
            return result;
        }

        if (BN_cmp(start_bn, end_bn) > 0) {
            std::swap(start_bn, end_bn);
        }

        std::cout << "Searching range: " << start_hex << " to " << end_hex << std::endl;
        if (num_threads <= 0) num_threads = 1;
        std::cout << "Using " << num_threads << " threads" << std::endl;
        std::cout << "Max iterations per thread: " << max_per_thread << std::endl;

        auto start_time = std::chrono::high_resolution_clock::now();

        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) {
            std::cerr << "Error: Failed to create BN_CTX" << std::endl;
            BN_free(start_bn);
            BN_free(end_bn);
            return result;
        }

        // Calculate range per thread: inclusive bounds
        BIGNUM* range_bn = BN_new();
        BIGNUM* thread_range_bn = BN_new();
        BIGNUM* thread_count_bn = BN_new();
        BIGNUM* one = BN_new();

        if (!range_bn || !thread_range_bn || !thread_count_bn || !one) {
            std::cerr << "Error: Failed to allocate BIGNUM for range calculation" << std::endl;
            if (range_bn) BN_free(range_bn);
            if (thread_range_bn) BN_free(thread_range_bn);
            if (thread_count_bn) BN_free(thread_count_bn);
            if (one) BN_free(one);
            BN_free(start_bn);
            BN_free(end_bn);
            BN_CTX_free(ctx);
            return result;
        }

        BN_sub(range_bn, end_bn, start_bn);    // range = end - start
        BN_set_word(one, 1);
        BN_add(range_bn, range_bn, one);       // inclusive: range = end - start + 1

        BN_set_word(thread_count_bn, static_cast<unsigned long>(num_threads));
        // thread_range = range / threads
        BN_div(thread_range_bn, nullptr, range_bn, thread_count_bn, ctx);
        // Ensure thread_range >= 1
        if (BN_is_zero(thread_range_bn)) {
            BN_set_word(thread_range_bn, 1);
        }

        std::vector<std::thread> threads;

        for (int i = 0; i < num_threads; ++i) {
            BIGNUM* thread_start = BN_new();
            BIGNUM* thread_end = BN_new();
            BIGNUM* i_bn = BN_new();
            BIGNUM* temp = BN_new();
            if (!thread_start || !thread_end || !i_bn || !temp) {
                if (thread_start) BN_free(thread_start);
                if (thread_end) BN_free(thread_end);
                if (i_bn) BN_free(i_bn);
                if (temp) BN_free(temp);
                continue;
            }

            BN_set_word(i_bn, static_cast<unsigned long>(i));
            BN_mul(temp, i_bn, thread_range_bn, ctx);           // temp = i * thread_range
            BN_add(thread_start, start_bn, temp);               // start + temp

            BN_copy(thread_end, thread_start);
            BN_add(thread_end, thread_end, thread_range_bn);    // start + (i+1)*thread_range
            BN_sub(thread_end, thread_end, one);                // inclusive end = above - 1

            // Clamp to global end
            if (BN_cmp(thread_end, end_bn) > 0) {
                BN_copy(thread_end, end_bn);
            }

            // Skip if start > end (possible last thread)
            if (BN_cmp(thread_start, thread_end) > 0) {
                BN_free(thread_start);
                BN_free(thread_end);
                BN_free(i_bn);
                BN_free(temp);
                continue;
            }

            threads.emplace_back([this, thread_start, thread_end, max_per_thread]() {
                try {
                    worker_thread_bignum(thread_start, thread_end, max_per_thread, 0);
                } catch (...) {
                    // swallow exceptions to avoid terminating process
                }
                BN_free(thread_start);
                BN_free(thread_end);
            });

            BN_free(i_bn);
            BN_free(temp);
        }

        // Progress monitoring
        std::thread progress_thread([this, start_time]() {
            using namespace std::chrono;
            while (!done_flag.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto current_time = high_resolution_clock::now();
                auto elapsed = duration_cast<std::chrono::seconds>(current_time - start_time).count();

                uint64_t current_processed = processed.load();
                if (elapsed > 0) {
                    double speed = static_cast<double>(current_processed) / std::max<int64_t>(1, elapsed);
                    std::cout << "\rProcessed: " << current_processed
                              << " @ " << std::fixed << std::setprecision(2)
                              << speed << " keys/s" << std::flush;
                }
            }
        });

        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
        done_flag.store(true);
        if (progress_thread.joinable()) progress_thread.join();

        std::cout << std::endl;

        auto end_time_tp = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::seconds>(end_time_tp - start_time).count();

        std::cout << "Search completed in " << total_time << " seconds." << std::endl;
        std::cout << "Total keys processed: " << processed.load() << std::endl;

        BN_free(start_bn);
        BN_free(end_bn);
        BN_free(range_bn);
        BN_free(thread_range_bn);
        BN_free(thread_count_bn);
        BN_free(one);
        BN_CTX_free(ctx);

        return result;
    }
};

#pragma GCC diagnostic pop

// Base58 and WIF
std::string base58_encode(const std::vector<uint8_t>& data) {
    const std::string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    BIGNUM* bn = BN_new();
    if (!bn) return "";

    BN_bin2bn(data.data(), static_cast<int>(data.size()), bn);

    std::string result;
    BIGNUM* base = BN_new();
    BIGNUM* remainder = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    if (!base || !remainder || !ctx) {
        if (bn) BN_free(bn);
        if (base) BN_free(base);
        if (remainder) BN_free(remainder);
        if (ctx) BN_CTX_free(ctx);
        return "";
    }

    BN_set_word(base, 58);

    BIGNUM* q = BN_new();
    if (!q) {
        BN_free(bn); BN_free(base); BN_free(remainder); BN_CTX_free(ctx);
        return "";
    }

    // Loop: bn = bn / base, remainder = bn % base
    while (!BN_is_zero(bn)) {
        if (!BN_div(q, remainder, bn, base, ctx)) {
            BN_free(bn); BN_free(base); BN_free(remainder); BN_free(q); BN_CTX_free(ctx);
            return "";
        }
        // Move quotient back to bn
        BN_copy(bn, q);
        unsigned long rem = BN_get_word(remainder);
        if (rem >= alphabet.size()) {
            BN_free(bn); BN_free(base); BN_free(remainder); BN_free(q); BN_CTX_free(ctx);
            return "";
        }
        result = alphabet[rem] + result;
    }

    // Handle leading zeros
    for (uint8_t byte : data) {
        if (byte == 0) {
            result = "1" + result;
        } else {
            break;
        }
    }

    BN_free(bn);
    BN_free(base);
    BN_free(remainder);
    BN_free(q);
    BN_CTX_free(ctx);

    return result;
}

std::string create_wif(const std::string& private_key_hex, bool compressed = true) {
    std::vector<uint8_t> data;
    data.reserve(1 + 32 + 1 + 4);
    data.push_back(0x80);

    for (size_t i = 0; i + 1 < private_key_hex.length(); i += 2) {
        std::string byte_str = private_key_hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        data.push_back(byte);
    }

    if (compressed) {
        data.push_back(0x01);
    }

    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    for (int i = 0; i < 4; ++i) {
        data.push_back(hash2[i]);
    }

    return base58_encode(data);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: " << argv[0] << " <table_file> <start_range_hex> <end_range_hex> [options]\n";
        std::cout << "Options:\n";
        std::cout << "  --threads <n>         Number of threads (default: hardware concurrency)\n";
        std::cout << "  --max-per-thread <n>  Max iterations per thread (default: 1000000)\n";
        std::cout << "  --bloom               Enable Bloom filter\n";
        std::cout << "  --bloom-fpr <f>       Bloom filter false positive rate (default: 0.001)\n";
        std::cout << "  --bloom-size <n>      Fixed Bloom filter size\n";
        std::cout << "\nNote: This version uses BIGNUM for large hex values and large decimal offsets\n";
        std::cout << "Example: " << argv[0] << " table.txt 8000000000 ffffffffff --threads 4\n";
        return 1;
    }

    std::string table_file = argv[1];
    std::string start_hex = argv[2];
    std::string end_hex = argv[3];

    int num_threads = std::thread::hardware_concurrency();
    uint64_t max_per_thread = 1000000;
    bool use_bloom = false;
    double bloom_fpr = 0.001;
    size_t bloom_size = 0;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--threads" && i + 1 < argc) {
            num_threads = std::stoi(argv[++i]);
        } else if (arg == "--max-per-thread" && i + 1 < argc) {
            max_per_thread = std::stoull(argv[++i]);
        } else if (arg == "--bloom") {
            use_bloom = true;
        } else if (arg == "--bloom-fpr" && i + 1 < argc) {
            bloom_fpr = std::stod(argv[++i]);
        } else if (arg == "--bloom-size" && i + 1 < argc) {
            bloom_size = std::stoull(argv[++i]);
        }
    }

    // Validate hex strings
    BIGNUM* test_start = hex_to_bignum(start_hex);
    BIGNUM* test_end = hex_to_bignum(end_hex);

    if (!test_start || !test_end) {
        std::cerr << "Error: Invalid hexadecimal range values" << std::endl;
        std::cerr << "Start: " << start_hex << std::endl;
        std::cerr << "End: " << end_hex << std::endl;
        if (test_start) BN_free(test_start);
        if (test_end) BN_free(test_end);
        return 1;
    }

    if (BN_cmp(test_start, test_end) > 0) {
        std::cerr << "Error: Start range is greater than end range" << std::endl;
        BN_free(test_start);
        BN_free(test_end);
        return 1;
    }

    BN_free(test_start);
    BN_free(test_end);

    try {
        XPointSearcher searcher;

        if (!searcher.load_table(table_file, use_bloom, bloom_fpr, bloom_size)) {
            return 1;
        }

        SearchResult result = searcher.search_bignum(start_hex, end_hex, num_threads, max_per_thread);

        if (result.found) {
            std::cout << "\n=== MATCH FOUND ===\n";
            std::cout << "r = 0x" << result.r_hex << std::endl;
            std::cout << "offset (dec) = " << result.offset_dec << std::endl;
            std::cout << "compressed pubkey = " << result.pub_compressed << std::endl;
            std::cout << "private key (hex) = " << result.private_key << std::endl;
            std::cout << "WIF compressed = " << create_wif(result.private_key, true) << std::endl;
            std::cout << "WIF uncompressed = " << create_wif(result.private_key, false) << std::endl;
        } else {
            std::cout << "No match found in the specified range." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}