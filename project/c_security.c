#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int CLIENT_STATE = 0;
/*
State Table:
    0: init, send cli hello
    1: waiting for ser hello
*/

uint8_t hostname[256];
uint8_t init_nonce[NONCE_SIZE];

void c_init_sec(int type, char *host)
{
    memcpy(hostname, host, strlen(host)); // save hostname??

    generate_private_key();
    derive_public_key();

    init_io();
}

ssize_t c_input_sec(uint8_t *buf, size_t max_length)
{
    if (CLIENT_STATE == 0)
    {
        // Create Client Hello
        tlv *cli_hello = create_tlv(CLIENT_HELLO);

        // do the nonce
        tlv *nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(cli_hello, nn);
        memcpy(init_nonce, nonce, NONCE_SIZE); // save nonce

        // do the generated public key
        tlv *pub_key = create_tlv(PUBLIC_KEY);
        add_val(pub_key, public_key, pub_key_size);
        add_tlv(cli_hello, pub_key);

        // serialize
        uint16_t len = serialize_tlv(buf, cli_hello);
        free_tlv(cli_hello);

        // update State
        CLIENT_STATE = 1;
        return len;
    }

    return input_io(buf, max_length);
}

void c_output_sec(uint8_t *buf, size_t length)
{
    if (CLIENT_STATE == 0)
        return; // need to send client hello first

    output_io(buf, length);
}
