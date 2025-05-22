#include <cctype>
#include <iostream>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <random>
#include <atomic>
#include <vector>
#include <fstream>
#include <condition_variable>
#include <chrono>
#include <iomanip>

#include "base58.hpp"
#include "include/secp256k1.h"
#include "config.h"
#include "Address.h"
#include "HexUtil.hpp"

#define PROGRAM_NAME "BitCrackCPU"

std::unordered_set<std::string> hash160_set;
std::mutex config_mutex;
std::mutex range_mutex;
std::mutex found_keys_mutex;
std::mutex speed_mutex;
std::condition_variable range_cv;
std::atomic<bool> shutdown_flag(false);
std::atomic<uint64_t> total_ranges_completed(0);
std::atomic<uint64_t> total_keys_processed(0);
std::chrono::time_point<std::chrono::steady_clock> start_time;

void decode_addresses_into_hash160(Config &config) {
  for (auto address : config.addresses) {
    auto hash160 = base58::ExtractHash160(address);
    auto hash160_hex = HexUtil::toHex(hash160.data(), 20);
    hash160_set.insert(hash160_hex);
  }
}

// Save found private key and address to file
void save_found_key(const std::string& privkey, const std::string& address, const std::string& found_keys_file) {
  std::lock_guard<std::mutex> lock(found_keys_mutex);
  std::ofstream file(found_keys_file, std::ios::app);
  if (file.is_open()) {
    file << "Private Key: 0x" << privkey << " Address: " << address << std::endl;
    file.close();
  } else {
    std::lock_guard<std::mutex> cerr_lock(config_mutex);
    std::cerr << "[!] Failed to write to found keys file: " << found_keys_file << std::endl;
  }
}

void scan_range(
  Secp256K1 *s,
  Int start,
  Int end,
  const std::string& found_keys_file
) {
  // Compute the start pubkey.
  Point current = s->ComputePublicKey(&start, true);

  Point G = s->G;

  while (start.IsLower(&end)) {
    std::vector<SerializedPubKey> pubkeys(8);
    for (int i = 0; i < 8; i++) {
      pubkeys[i] = Address::serialize_pubkey(current);
      current = s->NextKey(current);
    }

   std::vector<std::array<unsigned char, 65>> uncomp_pubkeys(8);
    std::vector<std::array<unsigned char, 33>> comp_pubkeys(8);
    for (int i = 0; i < 8; i++) {
      uncomp_pubkeys[i] = pubkeys[i].uncompressed;
      comp_pubkeys[i] = pubkeys[i].compressed;
    }

    const uint8_t *uncomp_pubkeys_ptrs[8];
    for (int i = 0; i < 8; i++) {
      uncomp_pubkeys_ptrs[i] = uncomp_pubkeys[i].data();
    }
    const size_t lengths[8] = {65, 65, 65, 65, 65, 65, 65, 65};
    std::vector<std::string> hash160_uncomp(8);

    for (int i = 0; i < 8; i++) {
      hash160_uncomp[i] =
        Address::pubkey_to_hash160_hex(uncomp_pubkeys_ptrs[i], lengths[i]);
    }
    
    const uint8_t *comp_pubkeys_ptrs[8];
    for (int i = 0; i < 8; i++) {
      comp_pubkeys_ptrs[i] = comp_pubkeys[i].data();
    }
    const size_t comp_lengths[8] = {33, 33, 33, 33, 33, 33, 33, 33};
    std::vector<std::string> hash160_comp(8);

    for (int i = 0; i < 8; i++) {
      hash160_comp[i] =
        Address::pubkey_to_hash160_hex(comp_pubkeys_ptrs[i], comp_lengths[i]);
    }

    for (int i = 0; i < 8; i++) {
      Int found_privkey = start;
      found_privkey.Add(i);
     
      bool found_uncomp = false;
      bool found_comp = false;
      std::string uncomp_hash = hash160_uncomp[i];
      std::string comp_hash = hash160_comp[i];
      
      found_uncomp = hash160_set.find(uncomp_hash) != hash160_set.end();
      found_comp = hash160_set.find(comp_hash) != hash160_set.end();

      if (found_uncomp) {
        auto address = Address::encodeP2PKH_Mainnet(uncomp_hash);
        auto privkey = found_privkey.GetBase16();
        {
          std::lock_guard<std::mutex> cout_lock(config_mutex);
          std::cout << "Found Private Key: 0x" << privkey << " Address: " << address << std::endl;
        }
        save_found_key(privkey, address, found_keys_file);
      }

      if (found_comp) {
        auto address = Address::encodeP2PKH_Mainnet(comp_hash);
        auto privkey = found_privkey.GetBase16();
        {
          std::lock_guard<std::mutex> cout_lock(config_mutex);
          std::cout << "Found Private Key: 0x" << privkey << " Address: " << address << std::endl;
        }
        save_found_key(privkey, address, found_keys_file);
      }
    }
    start.Add(8);
    // Increment keys processed counter
    total_keys_processed += 8;
  }
}

// Check if a range has already been scanned
bool is_range_scanned(const Int& range_start, const std::vector<Int*>& scanned_ranges) {
  for (const auto& range : scanned_ranges) {
    if (range->IsEqual(const_cast<Int*>(&range_start))) {
      return true;
    }
  }
  return false;
}

// Get a random unscanned range
bool get_random_range(Config& config, Int& range_start, Int& range_end) {
  std::lock_guard<std::mutex> lock(range_mutex);

  uint64_t num_ranges_int = config.total_ranges;
  
  // Check if all ranges are scanned
  if (config.scanned_ranges.size() >= num_ranges_int) {
    return false;
  }
  
  // Thread-local random generator
  static thread_local std::mt19937_64 gen(std::random_device{}());
  std::uniform_int_distribution<uint64_t> dist(0, num_ranges_int - 1);
  
  // Get a random unscanned range
  int max_attempts = 1000;
  int attempts = 0;
  
  while (attempts < max_attempts) {
    uint64_t range_idx = dist(gen);
    
    range_start = *config.range_start;
    Int range_size_multiplier(range_idx);
    range_size_multiplier.Mult(config.range_size);
    range_start.Add(&range_size_multiplier);
    
    range_end = range_start;
    range_end.Add(config.range_size);
    
    // Make sure range_end doesn't exceed the total range
    if (range_end.IsGreater(config.range_end)) {
      range_end.Set(config.range_end);
    }
    
    // Check if this range has already been scanned
    if (!is_range_scanned(range_start, config.scanned_ranges)) {
      // Mark this range as scanned immediately to prevent other workers from getting it
      Int* range_copy = new Int(range_start);
      config.scanned_ranges.push_back(range_copy);
      return true;
    }
    
    attempts++;
  }
  
  return false;
}

// Save a completed range to the config file
void save_completed_range(Config& config, const std::string& config_file, Int& range_start) {
  std::lock_guard<std::mutex> lock(config_mutex);
  
  // No need to add to scanned ranges again - already added in get_random_range
  // Just save to config file
  std::ofstream file(config_file, std::ios::app);
  if (file.is_open()) {
    file << "range: " << range_start.GetBase16() << std::endl;
    file.close();
    
    // Print progress
    uint64_t total_ranges = config.total_ranges;
    
    // Increment total ranges completed counter
    total_ranges_completed++;
    
    // Calculate and display speed
    auto now = std::chrono::steady_clock::now();
    auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    
    if (elapsed_seconds > 0) {
      // Calculate keys per second (ranges * range_size / seconds)
      double ranges_per_second = static_cast<double>(total_ranges_completed) / elapsed_seconds;
      double keys_per_second = ranges_per_second * std::stoull(config.range_size->GetBase10());
      
      std::lock_guard<std::mutex> speed_lock(speed_mutex);
      std::cout << "[+] Completed range: 0x" << range_start.GetBase16() 
                << " (" << config.scanned_ranges.size() << "/" 
                << total_ranges << ") - "
                << std::fixed << std::setprecision(2) << keys_per_second << " keys/sec" << std::endl;
    } else {
      std::cout << "[+] Completed range: 0x" << range_start.GetBase16() 
                << " (" << config.scanned_ranges.size() << "/" 
                << total_ranges << ")" << std::endl;
    }
  } else {
    std::cerr << "[!] Failed to update config file with completed range." << std::endl;
  }
}

// Worker thread function
void worker_thread(int worker_id, Config& config, const std::string& config_file) {
  {
    std::lock_guard<std::mutex> cout_lock(config_mutex);
    //std::cout << "[+] Starting worker " << worker_id << std::endl;
  }
  
  // Create secp256k1 context for this thread
  Secp256K1* s = new Secp256K1();
  s->Init();
  
  while (!shutdown_flag) {
    Int range_start, range_end;
    
    // Get a random range to scan
    if (!get_random_range(config, range_start, range_end)) {
      {
        std::lock_guard<std::mutex> cout_lock(config_mutex);
        std::cout << "[+] Worker " << worker_id << " found no more ranges to scan" << std::endl;
      }
      break;
    }
    
    {
      std::lock_guard<std::mutex> cout_lock(config_mutex);
      //std::cout << "[+] Worker " << worker_id << " scanning range: 0x" 
      //          << range_start.GetBase16() << " to 0x" << range_end.GetBase16() << std::endl;
    }
    
    // Scan the range
    scan_range(s, range_start, range_end, config.found_keys_file);
    
    // Save the completed range
    save_completed_range(config, config_file, range_start);
  }
  
  delete s;
  {
    std::lock_guard<std::mutex> cout_lock(config_mutex);
    std::cout << "[+] Worker " << worker_id << " finished" << std::endl;
  }
}

// Speed monitoring function that runs in a separate thread
void speed_monitor_thread() {
  auto last_update_time = std::chrono::steady_clock::now();
  uint64_t last_keys_processed = 0;
  
  while (!shutdown_flag) {
    // Update every second
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    auto now = std::chrono::steady_clock::now();
    auto total_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    auto update_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update_time).count();
    
    uint64_t current_keys = total_keys_processed;
    uint64_t keys_since_last = current_keys - last_keys_processed;
    
    if (update_elapsed > 0) {
      // Calculate current speed (keys processed in this interval)
      double current_keys_per_second = static_cast<double>(keys_since_last) / (update_elapsed / 1000.0);
      
      // Calculate average speed (all keys / total time)
      double avg_keys_per_second = total_elapsed > 0 ? 
                                    static_cast<double>(current_keys) / total_elapsed : 0;
      
      std::lock_guard<std::mutex> speed_lock(speed_mutex);
      std::cout << "\r[*] Speed: " << std::fixed << std::setprecision(2) 
                << current_keys_per_second << " keys/sec (avg: " 
                << avg_keys_per_second << " keys/sec)" << std::endl;
      
      // Update for next interval
      last_update_time = now;
      last_keys_processed = current_keys;
    }
  }
  std::cout << std::endl; // Add newline after last update
}

int main(int argc, char *argv[]) {
  std::cout << "[+] Starting BitCrackCPU" << std::endl;

  if (argc < 3) {
    std::cerr << "Usage: \n"
              << "  " << PROGRAM_NAME << " --create-config <config_file> \n"
              << "  " << PROGRAM_NAME << " --resume <config_file>" << std::endl;
    return 1;
  }

  std::string action = argv[1];
  std::string config_file = argv[2];

  if (action == "--create-config") {
    save_default_config(config_file);
    std::cout << "Config file created: " << config_file << std::endl;
    return 0;
  }
  std::cout << "[+] Loading config..." << std::endl;
  Config config;
  int result = load_config(config_file, config);
  if (result == -1) {
    std::cerr << "[!] Failed to load config. Exiting." << std::endl;
    return 1;
  }
  print_config(config);

  decode_addresses_into_hash160(config);
  std::cout << "[+] Loaded " << hash160_set.size() << " addresses into hash160 set." << std::endl;
  std::cout << "[+] Found keys will be saved to " << config.found_keys_file << std::endl;

  uint64_t total_ranges = config.total_ranges;

  uint64_t worker_count = config.workers;
  std::vector<std::thread> threads;
  
  // Initialize start time and reset counters
  start_time = std::chrono::steady_clock::now();
  total_ranges_completed = 0;
  total_keys_processed = 0;
  
  std::cout << "[+] Starting " << worker_count << " workers..." << std::endl;
  
  // Create and start worker threads
  for (uint64_t i = 0; i < worker_count; i++) {
    threads.push_back(std::thread(worker_thread, i, std::ref(config), std::ref(config_file)));
  }
  
  // Start speed monitoring thread
  std::thread monitor_thread(speed_monitor_thread);
  
  // Wait for user to press Ctrl+C or for all threads to complete
  std::cout << "[+] Press Ctrl+C to stop..." << std::endl;
  try {
    for (auto& thread : threads) {
      thread.join();
    }
    
    // Set shutdown flag to stop monitor thread
    shutdown_flag = true;
    if (monitor_thread.joinable()) {
      monitor_thread.join();
    }
  } catch (const std::exception& e) {
    // Set shutdown flag and wait for threads to complete
    shutdown_flag = true;
    range_cv.notify_all();
    
    for (auto& thread : threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
    
    if (monitor_thread.joinable()) {
      monitor_thread.join();
    }
  }
  
  // Calculate final statistics
  auto end_time = std::chrono::steady_clock::now();
  auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
  
  if (elapsed_seconds > 0 && total_keys_processed > 0) {
    double keys_per_second = static_cast<double>(total_keys_processed) / elapsed_seconds;
    
    std::cout << "[+] Average speed: " << std::fixed << std::setprecision(2) 
              << keys_per_second << " keys/sec" << std::endl;
  }
  
  std::cout << "[+] Completed. Scanned " << config.scanned_ranges.size() << " ranges." << std::endl;
  free_config(config);
  return 0;
}
