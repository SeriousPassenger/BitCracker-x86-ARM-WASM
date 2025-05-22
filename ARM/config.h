#pragma once

#include <vector>

#include "include/Int.h"

struct Config {
    Int *range_start;
    Int *range_end;
    Int *range_size;
    int workers;
    uint64_t total_ranges; // total number of ranges available
    std::vector<std::string> addresses;
    std::vector<Int *> scanned_ranges;
    std::string found_keys_file;
};

void save_default_config(std::string path);

int load_config(std::string path, Config &config);

void free_config(Config &config);

void print_config(Config &config);
