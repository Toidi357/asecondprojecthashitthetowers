#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void c_init_sec(char* host);

// Get input from security layer
ssize_t c_input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void c_output_sec(uint8_t* buf, size_t length);
