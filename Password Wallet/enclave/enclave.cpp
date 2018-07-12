#include "enclave_t.h"
#include "string.h"

#include "enclave.h"
#include "wallet.h"

#include "sgx_tseal.h"
#include "sealing/sealing.h"

int ecall_create_wallet(const char* master_password) {

	//
	// OVERVIEW: 
	//	1. check password policy
	//	2. [ocall] abort if wallet already exist
	//	3. create wallet 
	//	4. seal wallet
	//	5. [ocall] save wallet
	//	6. exit enclave
	//
	//
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;


	// 1. check passaword policy
	if (strlen(master_password) < 8 || strlen(master_password)+1 > MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}


	// 2. abort if wallet already exist
	ocall_status = ocall_is_wallet(&ocall_ret);
	if (ocall_ret != 0) {
		return ERR_WALLET_ALREADY_EXISTS;
	}


	// 3. create new wallet
	wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
	wallet->size = 0;
	strncpy(wallet->master_password, master_password, strlen(master_password)+1); 


	// 4. seal wallet
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t*)sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
		free(sealed_data);
		return ERR_FAIL_SEAL;
    }
    

	// 5. save wallet
	ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size); 
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return ERR_CANNOT_SAVE_WALLET;
	}


	// 6. exit enclave
	return RET_SUCCESS;
}


/**
 * @brief      Provides the wallet content. The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_show_wallet(const char* master_password, wallet_t* wallet, size_t wallet_size) {

	//
	// OVERVIEW: 
	//	1. [ocall] load wallet
	// 	2. unseal wallet
	//	3. verify master-password
	//	4. return wallet to app
	//	5. exit enclave
	//
	//
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;



	// 1. load wallet
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return ERR_CANNOT_LOAD_WALLET;
	}


	// 2. unseal loaded wallet
	uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t* unsealed_wallet = (wallet_t*)malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t*)sealed_data, unsealed_wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
		free(unsealed_wallet);
		return ERR_FAIL_UNSEAL;
    }
    
    
	// 3. verify master-password
	if (strcmp(unsealed_wallet->master_password, master_password) != 0) {
		free(unsealed_wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}


	// 4. return wallet to app
	(* wallet) = *unsealed_wallet;
	free(unsealed_wallet);


	// 5. exit enclave
	return RET_SUCCESS;
}


/**
 * @brief      Changes the wallet's master-password.
 *
 */
int ecall_change_master_password(const char* old_password, const char* new_password) {

	//
	// OVERVIEW: 
	//	1. check password policy
	//	2. [ocall] load wallet
	// 	3. unseal wallet
	//	4. verify old password
	//	5. update password
	//	6. seal wallet
	// 	7. [ocall] save sealed wallet
	//	8. exit enclave
	//
	//
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;



	// 1. check passaword policy
	if (strlen(new_password) < 8 || strlen(new_password)+1 > MAX_ITEM_SIZE) {
		return ERR_PASSWORD_OUT_OF_RANGE;
	}


	// 2. load wallet
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return ERR_CANNOT_LOAD_WALLET;
	}


	// 3. unseal wallet
	uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t* wallet = (wallet_t*)malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t*)sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
    	free(wallet);
		return ERR_FAIL_UNSEAL;
    }


	// 4. verify master-password
	if (strcmp(wallet->master_password, old_password) != 0) {
		free(wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}


	// 5. update password
	strncpy(wallet->master_password, new_password, strlen(new_password)+1); 


	// 6. seal wallet
	sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t*)sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
    	free(wallet);
		free(sealed_data);
		return ERR_FAIL_SEAL;
    }


	// 7. save wallet
	ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size); 
	free(sealed_data); 
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return ERR_CANNOT_SAVE_WALLET;
	}


	// 6. exit enclave
	return RET_SUCCESS;
}


/**
 * @brief      Adds an item to the wallet. The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_add_item(const char* master_password, const item_t* item, const size_t item_size) {

	//
	// OVERVIEW: 
	//	1. [ocall] load wallet
	//	2. unseal wallet
	//	3. verify master-password
	//	4. check input length
	//	5. add item to the wallet
	//	6. seal wallet
	//	7. [ocall] save sealed wallet
	//	8. exit enclave
	//
	//
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;



	// 2. load wallet
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return ERR_CANNOT_LOAD_WALLET;
	}


	// 3. unseal wallet
	uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t* wallet = (wallet_t*)malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t*)sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
    	free(wallet);
		return ERR_FAIL_UNSEAL;
    }


	// 3. verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		free(wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}


	// 4. check input length
	if (strlen(item->title)+1 > MAX_ITEM_SIZE ||
		strlen(item->username)+1 > MAX_ITEM_SIZE ||
		strlen(item->password)+1 > MAX_ITEM_SIZE
	) {
		free(wallet);
		return ERR_ITEM_TOO_LONG; 
    }


	// 5. add item to the wallet
	size_t wallet_size = wallet->size;
	if (wallet_size >= MAX_ITEMS) {
		free(wallet);
		return ERR_WALLET_FULL;
	}
	wallet->items[wallet_size] = *item;
	++wallet->size;


	// 6. seal wallet
	sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t*)sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
    	free(wallet);
		free(sealed_data);
		return ERR_FAIL_SEAL;
    }


	// 7. save wallet
	ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);  
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return ERR_CANNOT_SAVE_WALLET;
	}


	// 8. exit enclave
	return RET_SUCCESS;
}


/**
 * @brief      Removes an item from the wallet. The sizes/length of 
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_remove_item(const char* master_password, const int index) {

	//
	// OVERVIEW: 
	//	1. check index bounds
	//	2. [ocall] load wallet
	//	3. unseal wallet
	//	4. verify master-password
	//	5. remove item from the wallet
	//	6. seal wallet
	//	7. [ocall] save sealed wallet
	//	8. exit enclave
	//
	//
	sgx_status_t ocall_status, sealing_status;
	int ocall_ret;



	// 1. check index bounds
	if (index < 0 || index >= MAX_ITEMS) {
		return ERR_ITEM_DOES_NOT_EXIST;
	}


	// 2. load wallet
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
	ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		free(sealed_data);
		return ERR_CANNOT_LOAD_WALLET;
	}


	// 3. unseal wallet
	uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t* wallet = (wallet_t*)malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t*)sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
    	free(wallet);
		return ERR_FAIL_UNSEAL;
    }


	// 4. verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		free(wallet);
		return ERR_WRONG_MASTER_PASSWORD;
	}


	// 5. remove item from the wallet
	size_t wallet_size = wallet->size;
	if (index >= wallet_size) {
		free(wallet);
		return ERR_ITEM_DOES_NOT_EXIST;
	}
	for (int i = index; i < wallet_size-1; ++i) {
		wallet->items[i] = wallet->items[i+1];
	}
	--wallet->size;


	// 6. seal wallet
	sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t*)sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
		free(sealed_data);
		return ERR_FAIL_SEAL;
    }


	// 7. save wallet
	ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);  
	free(sealed_data);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return ERR_CANNOT_SAVE_WALLET;
	}


	// 8. exit enclave
	return RET_SUCCESS;
}

