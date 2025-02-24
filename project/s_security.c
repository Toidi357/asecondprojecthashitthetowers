#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int SERVER_STATE = 0;
/*
State Table:
    0: init, awaiting cli hello
    1: sending server hello
*/

uint8_t CLI_HELLO[1024];
size_t CLI_HELLO_SIZE;
uint8_t CLI_NONCE[NONCE_SIZE];
uint8_t SER_NONCE[NONCE_SIZE];
EVP_PKEY* EPHMERAL_PRIV_KEY;

void s_init_sec(int type, char *host)
{
    load_certificate("server_cert.bin");

    generate_private_key();
    derive_public_key();
    EPHMERAL_PRIV_KEY = get_private_key();

    init_io();
}

ssize_t s_input_sec(uint8_t *buf, size_t max_length)
{
    if (SERVER_STATE == 0)
        return 0; // no sending until we get a client hello

    if (SERVER_STATE == 1) // send server hello
    {
        // Create Server Hello
        tlv *ser_hello = create_tlv(SERVER_HELLO);

        // do the nonce
        tlv *nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ser_hello, nn);
        memcpy(SER_NONCE, nonce, NONCE_SIZE); // save nonce

        // do the certificate
        tlv *cert = deserialize_tlv(certificate, cert_size);
        add_tlv(ser_hello, cert);

        // do the generated public key
        tlv *pub_key = create_tlv(PUBLIC_KEY);
        add_val(pub_key, public_key, pub_key_size);
        add_tlv(ser_hello, pub_key);

        // do the signature
        load_private_key("server_key.bin");
        uint8_t signature[72];
        uint8_t signature_data[1024];
        size_t signature_data_size = CLI_HELLO_SIZE;
        memcpy(signature_data, CLI_HELLO, CLI_HELLO_SIZE);

        uint16_t lenn = serialize_tlv(buf, nn);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;
        
        memcpy(signature_data + signature_data_size, certificate, cert_size);
        signature_data_size += cert_size;

        lenn = serialize_tlv(buf, pub_key);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        tlv *signature_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        size_t sig_size = sign(signature, signature_data, signature_data_size);
        add_val(signature_tlv, signature, sig_size);
        add_tlv(ser_hello, signature_tlv);
        set_private_key(EPHMERAL_PRIV_KEY);

        // serialize
        uint16_t len = serialize_tlv(buf, ser_hello);
        free_tlv(ser_hello);

        // update State
        SERVER_STATE = 2;
        return len;
    }

    return input_io(buf, max_length);
}

void s_output_sec(uint8_t *buf, size_t length)
{
    if (SERVER_STATE == 0) // expect client hello
    {
        // save the entire client hello to use for server hello signature generation
        memcpy(CLI_HELLO, buf, length);
        CLI_HELLO_SIZE = length;

        // deserialize the packet
        tlv *cli_hello = deserialize_tlv(buf, length);
        if (cli_hello == NULL)
            return;
        tlv *nn = get_tlv(cli_hello, NONCE);
        tlv *cli_pub_key = get_tlv(cli_hello, PUBLIC_KEY);

        // save the client's ephermeral public key and initial nonce
        memcpy(CLI_NONCE, nn->val, nn->length);
        load_peer_public_key(cli_pub_key->val, cli_pub_key->length);  

        // update State
        SERVER_STATE = 1;
        return;
    }
    
    output_io(buf, length);
}
