#include "enclave_u.h"
#include "sgx_urts.h"

#include <cstring>
#include <fstream>
#include <getopt.h>

#include "app.h"
#include "utils.h"
#include "wallet.h"
#include "enclave.h"

using namespace std;


// OCALLs implementation
int ocall_save_wallet(const uint8_t* sealed_data, const size_t sealed_size) {
    ofstream file(WALLET_FILE, ios::out | ios::binary);
    if (file.fail()) {return 1;}
    file.write((const char*) sealed_data, sealed_size);
    file.close();
    return 0;
}

int ocall_load_wallet(uint8_t* sealed_data, const size_t sealed_size) {
    ifstream file(WALLET_FILE, ios::in | ios::binary);
    if (file.fail()) {return 1;}
    file.read((char*) sealed_data, sealed_size);
    file.close();
    return 0;
}

int ocall_is_wallet(void) {
    ifstream file(WALLET_FILE, ios::in | ios::binary);
    if (file.fail()) {return 0;} // failure means no wallet found
    file.close();
    return 1;
}

int main(int argc, char** argv) {

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated, ret;
    sgx_status_t ecall_status, enclave_status;

    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if(enclave_status != SGX_SUCCESS) {
        error_print("Fail to initialize enclave."); 
        return -1;
    }
    info_print("Enclave successfully initilised.");

    const char* options = "hvn:p:c:sax:y:z:r:";
    opterr=0; // prevent 'getopt' from printing err messages
    char err_message[100];
    int opt, stop=0;
    int h_flag=0, v_flag=0, s_flag=0, a_flag=0;
    char * n_value=NULL, *p_value=NULL, *c_value=NULL, *x_value=NULL, *y_value=NULL, *z_value=NULL, *r_value=NULL;
  
    // read user input
    while ((opt = getopt(argc, argv, options)) != -1) {
        switch (opt) {
            // help
            case 'h':
                h_flag = 1;
                break;

            // create new wallet
            case 'n':
                n_value = optarg;
                break;

            // master-password
            case 'p':
                p_value = optarg;
                break;

            // change master-password
            case 'c':
                c_value = optarg;
                break;

            // show wallet
            case 's':
                s_flag = 1;
                break;

            // add item
            case 'a': // add item flag
                a_flag = 1;
                break;
            case 'x': // item's title
                x_value = optarg;
                break;
            case 'y': // item's username
                y_value = optarg;
                break;
            case 'z': // item's password
                z_value = optarg;
                break;

            // remove item
            case 'r':
                r_value = optarg;
                break;

            // exceptions
            case '?':
                if (optopt == 'n' || optopt == 'p' || optopt == 'c' || optopt == 'r' ||
                    optopt == 'x' || optopt == 'y' || optopt == 'z'
                ) {
                    sprintf(err_message, "Option -%c requires an argument.", optopt);
                }
                else if (isprint(optopt)) {
                    sprintf(err_message, "Unknown option `-%c'.", optopt);
                }
                else {
                    sprintf(err_message, "Unknown option character `\\x%x'.",optopt);
                }
                stop = 1;
                error_print(err_message);
                error_print("Program exiting.");
                break;

            default:
                error_print("Unknown option.");
        }
    }

    // perform actions
    if (stop != 1) {
        // show help
        if (h_flag) {
            show_help();
        }

        // create new wallet
        else if(n_value!=NULL) {
            ecall_status = ecall_create_wallet(eid, &ret, n_value);
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail to create new wallet.");
            }
            else {
                info_print("Wallet successfully created.");
            }
        }

        // change master-password
        else if (p_value!=NULL && c_value!=NULL) {
            ecall_status = ecall_change_master_password(eid, &ret, p_value, c_value);
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail change master-password.");
            }
            else {
                info_print("Master-password successfully changed.");
            }
        }

        // show wallet
        else if(p_value!=NULL && s_flag) {
            wallet_t* wallet = (wallet_t*)malloc(sizeof(wallet_t));
            ecall_status = ecall_show_wallet(eid, &ret, p_value, wallet, sizeof(wallet_t));
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail to retrieve wallet.");
            }
            else {
                info_print("Wallet successfully retrieved.");
                print_wallet(wallet);
            }
            free(wallet);
        }

        // add item
        else if (p_value!=NULL && a_flag && x_value!=NULL && y_value!=NULL && z_value!=NULL) {
            item_t* new_item = (item_t*)malloc(sizeof(item_t));
            strcpy(new_item->title, x_value); 
            strcpy(new_item->username, y_value); 
            strcpy(new_item->password, z_value);
            ecall_status = ecall_add_item(eid, &ret, p_value, new_item, sizeof(item_t));
            if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                error_print("Fail to add new item to wallet.");
            }
            else {
                info_print("Item successfully added to the wallet.");
            }
            free(new_item);
        }

        // remove item
        else if (p_value!=NULL && r_value!=NULL) {
            char* p_end;
            int index = (int)strtol(r_value, &p_end, 10);
            if (r_value == p_end) {
                error_print("Option -r requires an integer argument.");
            }
            else {
                ecall_status = ecall_remove_item(eid, &ret, p_value, index);
                if (ecall_status != SGX_SUCCESS || is_error(ret)) {
                    error_print("Fail to remove item.");
                }
                else {
                    info_print("Item successfully removed from the wallet.");
                }
            }
        }

        // display help
        else {
            error_print("Wrong inputs.");
            show_help();
        }
    }
    
    // destroy enclave
    enclave_status = sgx_destroy_enclave(eid);
    if(enclave_status != SGX_SUCCESS) {
        error_print("Fail to destroy enclave."); 
        return -1;
    }
    info_print("Enclave successfully destroyed.");

    info_print("Program exit success.");
    return 0;
}
