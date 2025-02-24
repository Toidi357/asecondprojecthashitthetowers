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
    2: keys generated, waiting to send finished message
    3: good to go
*/

uint8_t hostname[256];
uint8_t C_CLI_HELLO[1024];
size_t C_CLI_HELLO_SIZE;
uint8_t C_SER_HELLO[1024];
size_t C_SER_HELLO_SIZE;

void c_init_sec(char *host)
{
    memcpy(hostname, host, strlen(host)); // save hostname??

    load_ca_public_key("ca_public_key.bin");

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

        // do the generated public key
        tlv *pub_key = create_tlv(PUBLIC_KEY);
        add_val(pub_key, public_key, pub_key_size);
        add_tlv(cli_hello, pub_key);

        // serialize
        uint16_t len = serialize_tlv(buf, cli_hello);
        memcpy(C_CLI_HELLO, buf, len); // save client hello
        C_CLI_HELLO_SIZE = len;
        free_tlv(cli_hello);

        // update State
        CLIENT_STATE = 1;
        return len;
    }

    if (CLIENT_STATE == 1) // waiting for server hello
        return 0;

    if (CLIENT_STATE == 2) // send finished message
    {
        uint8_t data[1024];
        size_t data_size = C_CLI_HELLO_SIZE + C_SER_HELLO_SIZE;
        memcpy(data, C_CLI_HELLO, C_CLI_HELLO_SIZE);
        memcpy(data + C_CLI_HELLO_SIZE, C_SER_HELLO, C_SER_HELLO_SIZE);

        // create MAC digest
        uint8_t digest[MAC_SIZE];
        hmac(digest, data, data_size);

        // build Transcript TLV
        tlv *transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, digest, MAC_SIZE);

        // build Finished TLV
        tlv *finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);

        // serialize
        uint16_t len = serialize_tlv(buf, finished);
        free_tlv(finished);

        // update State
        CLIENT_STATE = 3;
        return len;
    }

    if (CLIENT_STATE == 3)
    {
        size_t bytes_read = input_io(buf, 943);

        if (bytes_read == 0)
            return 0;

        tlv *data = create_tlv(DATA);
        tlv *iv = create_tlv(IV);
        tlv *ciphertext = create_tlv(CIPHERTEXT);
        tlv *mac = create_tlv(MAC);

        // generate an IV
        uint8_t temp[1024];
        generate_nonce(temp, IV_SIZE);
        add_val(iv, temp, IV_SIZE);

        // generate ciphertext tlv
        size_t ciphertext_size = encrypt_data(iv->val, temp, buf, bytes_read);
        add_val(ciphertext, temp, ciphertext_size);

        // generate MAC
        uint8_t _[1024];
        serialize_tlv(_, iv);
        uint16_t lenn = serialize_tlv(_ + 18, ciphertext);
        hmac(temp, _, lenn + 18); // size of IV TLV is always 18 bytes
        add_val(mac, temp, MAC_SIZE);

        // build and send out
        add_tlv(data, iv);
        add_tlv(data, ciphertext);
        add_tlv(data, mac);
        uint16_t len = serialize_tlv(buf, data);
        free_tlv(data);
        return len;
    }
}

void c_output_sec(uint8_t *buf, size_t length)
{
    if (CLIENT_STATE == 0)
        return; // need to send client hello first

    if (CLIENT_STATE == 1) // parse the server hello
    {
        // save the entire server hello to use for key exchange
        memcpy(C_SER_HELLO, buf, length);
        C_SER_HELLO_SIZE = length;

        tlv *ser_hello = deserialize_tlv(buf, length);
        if (ser_hello == NULL)
            return;

        // verify certificate
        tlv *cert = get_tlv(ser_hello, CERTIFICATE);
        tlv *cert_dns = get_tlv(cert, DNS_NAME);
        tlv *cert_pub_key = get_tlv(cert, PUBLIC_KEY);
        load_peer_public_key(cert_pub_key->val, cert_pub_key->length);
        tlv *cert_sig = get_tlv(cert, SIGNATURE);

        uint8_t signature_data[1024];
        size_t signature_data_size = 0;
        uint16_t lenn = serialize_tlv(buf, cert_dns);
        memcpy(signature_data, buf, lenn);
        signature_data_size += lenn;
        lenn = serialize_tlv(buf, cert_pub_key);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        if (verify(cert_sig->val, cert_sig->length, signature_data, signature_data_size, ec_ca_public_key) != 1)
        {
            fprintf(stderr, "Bad Cert\n");
            exit(1);
        }
        // END of verify certificate

        // verify DNS hostname
        if (strncmp((char *)hostname, (char *)(cert_dns->val), cert_dns->length) != 0)
        {
            fprintf(stderr, "Bad Hostname\n");
            exit(2);
        }

        // verify signature
        tlv *sign = get_tlv(ser_hello, HANDSHAKE_SIGNATURE);
        tlv *nn = get_tlv(ser_hello, NONCE);
        tlv *pub_key = get_tlv(ser_hello, PUBLIC_KEY);

        signature_data_size = 0;
        memcpy(signature_data, C_CLI_HELLO, C_CLI_HELLO_SIZE);
        signature_data_size += C_CLI_HELLO_SIZE;

        lenn = serialize_tlv(buf, nn);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        lenn = serialize_tlv(buf, cert);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        lenn = serialize_tlv(buf, pub_key);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        if (verify(sign->val, sign->length, signature_data, signature_data_size, ec_peer_public_key) != 1)
        {
            fprintf(stderr, "Bad Handshake Signature\n");
            exit(3);
        }
        // END of verify signature

        // perform key exchange
        load_peer_public_key(pub_key->val, pub_key->length);
        derive_secret();
        uint8_t salt[1024];
        size_t salt_size = C_CLI_HELLO_SIZE + C_SER_HELLO_SIZE;
        memcpy(salt, C_CLI_HELLO, C_CLI_HELLO_SIZE);
        memcpy(salt + C_CLI_HELLO_SIZE, C_SER_HELLO, C_SER_HELLO_SIZE);
        derive_keys(salt, salt_size);

        free_tlv(ser_hello);
        CLIENT_STATE = 2;
        return;
    }

    if (CLIENT_STATE == 2)
        return;

    if (CLIENT_STATE == 3)
    {
        tlv *recvd = deserialize_tlv(buf, length);
        if (recvd == NULL)
            return;

        tlv *iv = get_tlv(recvd, IV);
        tlv *ciphertext = get_tlv(recvd, CIPHERTEXT);
        tlv *mac = get_tlv(recvd, MAC);

        uint8_t temp[1024];

        // verify mac
        uint8_t digest[MAC_SIZE];
        serialize_tlv(temp, iv);
        uint16_t lenn = serialize_tlv(temp + 18, ciphertext); // size of IV TLV is always 18 bytes
        hmac(digest, temp, lenn + 18);
        if (strncmp((char *)digest, (char *)(mac->val), MAC_SIZE) != 0)
        {
            fprintf(stderr, "Bad MAC\n");
            exit(5);
        }

        // decrypt text
        size_t bytes_recvd = decrypt_cipher(buf, ciphertext->val, ciphertext->length, iv->val);

        free_tlv(recvd);

        output_io(buf, bytes_recvd);
    }
}
