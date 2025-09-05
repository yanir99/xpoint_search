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

// OpenSSL includes for secp256k1
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

class BloomFilter {
private:
    std::vector<uint8_t> bit_array;
    size_t size;
    int hash_count;
    
    std::vector<size_t> get_hashes(const std::string& item) const {
        std::vector<size_t> hashes;
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
        double m = -(n_items * std::log(false_positive_rate)) / (std::log(2) * std::log(2));
        size = static_cast<size_t>(m);
        hash_count = std::max(1, static_cast<int>((size / static_cast<double>(n_items)) * std::log(2)));
        bit_array.resize(size, 0);
    }
    
    BloomFilter(size_t n_items, size_t fixed_size) {
        size = fixed_size;
        hash_count = std::max(1, static_cast<int>((size / static_cast<double>(n_items)) * std::log(2)));
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
            if (!bit_array[idx]) return false;
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
        generator = EC_POINT_new(group);
        order = BN_new();
        EC_GROUP_get_order(group, order, nullptr);
        
        const EC_POINT* gen = EC_GROUP_get0_generator(group);
        EC_POINT_copy(generator, gen);
    }
    
    ~SECP256K1() {
        EC_GROUP_free(group);
        EC_POINT_free(generator);
        BN_free(order);
    }
    
    std::string compress_point(const EC_POINT* point) const {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        
        EC_POINT_get_affine_coordinates_GFp(group, point, x, y, nullptr);
        
        std::string result;
        if (BN_is_odd(y)) {
            result = "03";
        } else {
            result = "02";
        }
        
        char* x_hex = BN_bn2hex(x);
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
    
    EC_POINT* multiply(const BIGNUM* scalar) const {
        EC_POINT* result = EC_POINT_new(group);
        EC_POINT_mul(group, result, scalar, nullptr, nullptr, nullptr);
        return result;
    }
    
    EC_GROUP* get_group() const { return group; }
    BIGNUM* get_order() const { return order; }
};

struct SearchResult {
    bool found;
    uint64_t r;
    int64_t offset;
    std::string pub_compressed;
    std::string private_key;
};

class XPointSearcher {
private:
    std::unordered_map<std::string, int64_t> table;
    std::unique_ptr<BloomFilter> bloom;
    SECP256K1 secp;
    std::atomic<uint64_t> processed{0};
    std::atomic<bool> found_flag{false};
    SearchResult result;
    std::mutex result_mutex;
    
    bool load_table_chunked(const std::string& filename, bool use_bloom, 
                           double bloom_fpr, size_t bloom_size) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open table file: " << filename << std::endl;
            return false;
        }
        
        std::vector<int64_t> offsets;
        std::string line;
        size_t line_count = 0;
        
        std::cout << "Loading table..." << std::endl;
        while (std::getline(file, line)) {
            if (line.empty() || (!line.starts_with("02") && !line.starts_with("03"))) {
                continue;
            }
            
            size_t hash_pos = line.find('#');
            if (hash_pos == std::string::npos) continue;
            
            std::string hex_part = line.substr(0, hash_pos);
            hex_part.erase(hex_part.find_last_not_of(" \t") + 1);
            
            std::string offset_str = line.substr(hash_pos + 1);
            offset_str.erase(0, offset_str.find_first_not_of(" \t"));
            
            try {
                int64_t offset = std::stoll(offset_str);
                table[hex_part] = offset;
                if (offset != 0) {
                    offsets.push_back(std::abs(offset));
                }
                line_count++;
                
                if (line_count % 10000000 == 0) {
                    std::cout << "Loaded " << line_count << " entries..." << std::endl;
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
        
        if (offsets.empty()) {
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
    
    void worker_thread(uint64_t start, uint64_t end, int thread_id) {
        BIGNUM* r_bn = BN_new();
        
        for (uint64_t r = start; r < end && !found_flag.load(); ++r) {
            BN_set_word(r_bn, r);
            EC_POINT* point = secp.multiply(r_bn);
            
            std::string comp_hex = secp.compress_point(point);
            
            if (bloom && !bloom->contains(comp_hex)) {
                EC_POINT_free(point);
                continue;
            }
            
            auto it = table.find(comp_hex);
            if (it != table.end()) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!found_flag.load()) {
                    found_flag.store(true);
                    result.found = true;
                    result.r = r;
                    result.offset = it->second;
                    result.pub_compressed = comp_hex;
                    
                    BIGNUM* priv_bn = BN_new();
                    BIGNUM* offset_bn = BN_new();
                    BN_set_word(r_bn, r);
                    
                    if (it->second >= 0) {
                        BN_set_word(offset_bn, it->second);
                        BN_mod_sub(priv_bn, r_bn, offset_bn, secp.get_order(), nullptr);
                    } else {
                        BN_set_word(offset_bn, -it->second);
                        BN_mod_add(priv_bn, r_bn, offset_bn, secp.get_order(), nullptr);
                    }
                    
                    char* priv_hex = BN_bn2hex(priv_bn);
                    result.private_key = std::string(priv_hex);
                    OPENSSL_free(priv_hex);
                    
                    std::transform(result.private_key.begin(), result.private_key.end(), 
                                 result.private_key.begin(), ::tolower);
                    while (result.private_key.length() < 64) {
                        result.private_key = "0" + result.private_key;
                    }
                    
                    BN_free(priv_bn);
                    BN_free(offset_bn);
                }
            }
            
            EC_POINT_free(point);
            processed.fetch_add(1);
        }
        
        BN_free(r_bn);
    }
    
public:
    bool load_table(const std::string& filename, bool use_bloom = false, 
                   double bloom_fpr = 0.001, size_t bloom_size = 0) {
        return load_table_chunked(filename, use_bloom, bloom_fpr, bloom_size);
    }
    
    SearchResult search(uint64_t start_range, uint64_t end_range, 
                       int num_threads = std::thread::hardware_concurrency(),
                       uint64_t batch_size = 100000, bool random_search = false) {
        
        result = SearchResult{false, 0, 0, "", ""};
        found_flag.store(false);
        processed.store(0);
        
        uint64_t total_range = end_range - start_range + 1;
        std::cout << "Searching range: 0x" << std::hex << start_range 
                  << " to 0x" << end_range << std::dec << std::endl;
        std::cout << "Total range: " << total_range << " keys" << std::endl;
        std::cout << "Using " << num_threads << " threads" << std::endl;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (random_search) {
            std::vector<std::thread> threads;
            std::random_device rd;
            
            for (int i = 0; i < num_threads; ++i) {
                threads.emplace_back([this, start_range, end_range, batch_size, i, &rd]() {
                    std::mt19937_64 gen(rd() + i);
                    std::uniform_int_distribution<uint64_t> dist(start_range, end_range);
                    
                    while (!found_flag.load()) {
                        uint64_t random_start = dist(gen);
                        uint64_t random_end = std::min(random_start + batch_size, end_range + 1);
                        worker_thread(random_start, random_end, i);
                    }
                });
            }
            
            std::thread progress_thread([this, start_time, total_range]() {
                while (!found_flag.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    auto current_time = std::chrono::high_resolution_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
                    uint64_t current_processed = processed.load();
                    
                    if (elapsed > 0) {
                        double speed = static_cast<double>(current_processed) / elapsed;
                        std::cout << "\rProcessed: " << current_processed 
                                  << " @ " << std::fixed << std::setprecision(2) 
                                  << speed << " keys/s" << std::flush;
                    }
                }
            });
            
            for (auto& t : threads) {
                t.join();
            }
            progress_thread.join();
            
        } else {
            std::vector<std::thread> threads;
            uint64_t chunk_size = total_range / num_threads;
            
            for (int i = 0; i < num_threads; ++i) {
                uint64_t thread_start = start_range + i * chunk_size;
                uint64_t thread_end = (i == num_threads - 1) ? end_range + 1 : thread_start + chunk_size;
                
                threads.emplace_back(&XPointSearcher::worker_thread, this, 
                                   thread_start, thread_end, i);
            }
            
            std::thread progress_thread([this, start_time, total_range]() {
                while (!found_flag.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    auto current_time = std::chrono::high_resolution_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
                    uint64_t current_processed = processed.load();
                    
                    if (elapsed > 0) {
                        double speed = static_cast<double>(current_processed) / elapsed;
                        double percentage = (static_cast<double>(current_processed) / total_range) * 100.0;
                        std::cout << "\rProgress: " << current_processed << "/" << total_range 
                                  << " (" << std::fixed << std::setprecision(2) << percentage << "%) @ " 
                                  << speed << " keys/s" << std::flush;
                    }
                }
            });
            
            for (auto& t : threads) {
                t.join();
            }
            progress_thread.join();
        }
        
        std::cout << std::endl;
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
        
        std::cout << "Search completed in " << total_time << " seconds." << std::endl;
        std::cout << "Total keys processed: " << processed.load() << std::endl;
        
        return result;
    }
};

std::string base58_encode(const std::vector<uint8_t>& data) {
    const std::string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    BIGNUM* bn = BN_new();
    BN_bin2bn(data.data(), data.size(), bn);
    
    std::string result;
    BIGNUM* base = BN_new();
    BIGNUM* remainder = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    
    BN_set_word(base, 58);
    
    while (!BN_is_zero(bn)) {
        BN_div(bn, remainder, bn, base, ctx);
        result = alphabet[BN_get_word(remainder)] + result;
    }
    
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
    BN_CTX_free(ctx);
    
    return result;
}

std::string create_wif(const std::string& private_key_hex, bool compressed = true) {
    std::vector<uint8_t> data;
    data.push_back(0x80);
    
    for (size_t i = 0; i < private_key_hex.length(); i += 2) {
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
        std::cout << "  --threads <n>     Number of threads (default: hardware concurrency)\n";
        std::cout << "  --batch <n>       Batch size (default: 100000)\n";
        std::cout << "  --bloom           Enable Bloom filter\n";
        std::cout << "  --bloom-fpr <f>   Bloom filter false positive rate (default: 0.001)\n";
        std::cout << "  --bloom-size <n>  Fixed Bloom filter size\n";
        std::cout << "  --random          Use random search instead of sequential\n";
        return 1;
    }
    
    std::string table_file = argv[1];
    std::string start_hex = argv[2];
    std::string end_hex = argv[3];
    
    int num_threads = std::thread::hardware_concurrency();
    uint64_t batch_size = 100000;
    bool use_bloom = false;
    double bloom_fpr = 0.001;
    size_t bloom_size = 0;
    bool random_search = false;
    
    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--threads" && i + 1 < argc) {
            num_threads = std::stoi(argv[++i]);
        } else if (arg == "--batch" && i + 1 < argc) {
            batch_size = std::stoull(argv[++i]);
        } else if (arg == "--bloom") {
            use_bloom = true;
        } else if (arg == "--bloom-fpr" && i + 1 < argc) {
            bloom_fpr = std::stod(argv[++i]);
        } else if (arg == "--bloom-size" && i + 1 < argc) {
            bloom_size = std::stoull(argv[++i]);
        } else if (arg == "--random") {
            random_search = true;
        }
    }
    
    uint64_t start_range = std::stoull(start_hex, nullptr, 16);
    uint64_t end_range = std::stoull(end_hex, nullptr, 16);
    
    XPointSearcher searcher;
    
    if (!searcher.load_table(table_file, use_bloom, bloom_fpr, bloom_size)) {
        return 1;
    }
    
    SearchResult result = searcher.search(start_range, end_range, num_threads, batch_size, random_search);
    
    if (result.found) {
        std::cout << "\n=== MATCH FOUND ===\n";
        std::cout << "r = " << result.r << std::endl;
        std::cout << "offset = " << result.offset << std::endl;
        std::cout << "compressed pubkey = " << result.pub_compressed << std::endl;
        std::cout << "private key (hex) = " << result.private_key << std::endl;
        std::cout << "WIF compressed = " << create_wif(result.private_key, true) << std::endl;
        std::cout << "WIF uncompressed = " << create_wif(result.private_key, false) << std::endl;
    } else {
        std::cout << "No match found in the specified range." << std::endl;
    }
    
    return 0;
}