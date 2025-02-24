#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void s_init_sec(int type, char* host);

// Get input from security layer
ssize_t s_input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void s_output_sec(uint8_t* buf, size_t length);
