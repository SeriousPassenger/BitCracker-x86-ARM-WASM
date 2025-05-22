#include "config.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

int load_config(std::string path, Config &config) {
    config.range_start = new Int();
    config.range_end = new Int();
    config.range_size = new Int();
    config.workers = 1;
    config.addresses = std::vector<std::string>();
    config.scanned_ranges = std::vector<Int *>();
    config.found_keys_file = "found_keys.txt";
    config.total_ranges = 0;
    
    // Track required fields
    bool has_range_start = false;
    bool has_range_end = false;
    bool has_range_size = false;
    bool has_workers = false;
    bool has_address = false;
    
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Could not open config file: " << path << std::endl;
        return -1;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, value;
        
        if (std::getline(iss, key, ':') && std::getline(iss, value)) {
            // Trim leading whitespace from value
            value.erase(0, value.find_first_not_of(" \t"));
            
            if (key == "range_start") {
                config.range_start->SetBase16((char*)value.c_str());
                has_range_start = true;
            } else if (key == "range_end") {
                config.range_end->SetBase16((char*)value.c_str());
                has_range_end = true;
            } else if (key == "range_size") {
                config.range_size->SetBase16((char*)value.c_str());
                has_range_size = true;
            } else if (key == "workers") {
                try {
                    config.workers = std::stoi(value);
                    has_workers = true;
                } catch (const std::exception& e) {
                    std::cerr << "Error parsing workers: " << e.what() << std::endl;
                    file.close();
                    free_config(config);
                    return -1;
                }
            } else if (key == "address") {
                config.addresses.push_back(value);
                has_address = true;
            } else if (key == "range") {
                Int* range = new Int();
                range->SetBase16((char*)value.c_str());
                config.scanned_ranges.push_back(range);
            } else if (key == "found_keys_file") {
                config.found_keys_file = value;
            }
        }
    }
    
    file.close();
    
    // Verify all required fields are present
    if (!has_range_start || !has_range_end || !has_range_size || !has_workers || !has_address) {
        std::cerr << "Missing required fields in config file" << std::endl;
        free_config(config);
        return -1;
    }

    // Pre-compute total number of ranges
    Int total_ranges = *config.range_end;
    total_ranges.Sub(config.range_start);
    total_ranges.Div(config.range_size);
    Int uint64_max(UINT64_MAX);
    if (total_ranges.IsGreater(&uint64_max)) {
        config.total_ranges = UINT64_MAX;
    } else {
        config.total_ranges = std::stoull(total_ranges.GetBase10());
    }

    return 0;
}

void free_config(Config &config) {
    delete config.range_start;
    delete config.range_end;
    delete config.range_size;
    
    for (Int *range : config.scanned_ranges) {
        delete range;
    }
    config.scanned_ranges.clear();
}

void save_default_config(std::string path) {
    Config config;
    
    // Create range_start with value 0x1
    config.range_start = new Int();
    std::string start_hex = "0x1";
    config.range_start->SetBase16((char*)start_hex.c_str());
    
    // Create range_end with value 0xffffffff
    config.range_end = new Int();
    std::string end_hex = "0xFFFFFFFF";
    config.range_end->SetBase16((char*)end_hex.c_str());
    
    // Create range_size with value 0x1000
    config.range_size = new Int();
    std::string size_hex = "0x1000";
    config.range_size->SetBase16((char*)size_hex.c_str());
    
    config.workers = 1;
    config.addresses = {"1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"};
    config.scanned_ranges = std::vector<Int *>();
    config.found_keys_file = "found_keys.txt";

    std::ofstream file(path);
    
    file << "range_start: " << config.range_start->GetBase16() << std::endl;
    file << "range_end: " << config.range_end->GetBase16() << std::endl;
    file << "range_size: " << config.range_size->GetBase16() << std::endl;
    file << "workers: " << config.workers << std::endl;
    for (std::string address : config.addresses) {
        file << "address: " << address << std::endl;
    }
    for (Int *range : config.scanned_ranges) {
        file << "range: " << range->GetBase16() << std::endl;
    }
    file << "found_keys_file: " << config.found_keys_file << std::endl;
    file.close();
    
    // Free memory
    free_config(config);
}

void print_config(Config &config) {
    
    std::cout << "================================================" << std::endl;
    std::cout << "Range start:   " << "0x" << config.range_start->GetBase16() << std::endl;
    std::cout << "Range end:     " << "0x" << config.range_end->GetBase16() << std::endl;
    std::cout << "Range size:    " << "0x" << config.range_size->GetBase16() << std::endl;
    std::cout << "Addresses:     " << config.addresses.size() << std::endl;
    std::cout << "Scanned:       " << config.scanned_ranges.size() << "/" << config.total_ranges << std::endl;
    std::cout << "Workers:       " << config.workers << std::endl;
    std::cout << "Found keys:    " << config.found_keys_file << std::endl;
    std::cout << "================================================" << std::endl;
}
