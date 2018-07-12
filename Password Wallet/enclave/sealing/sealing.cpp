#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "wallet.h"
#include "sealing.h"

sgx_status_t seal_wallet(const wallet_t* wallet, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    return sgx_seal_data(0, NULL, sizeof(wallet_t), (uint8_t*)wallet, sealed_size, sealed_data);
}

sgx_status_t unseal_wallet(const sgx_sealed_data_t* sealed_data, wallet_t* plaintext, uint32_t plaintext_size) {
    return sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_size);
}

