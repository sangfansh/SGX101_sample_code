#ifndef WALLET_H_
#define WALLET_H_

#define MAX_ITEMS 100
#define MAX_ITEM_SIZE 100

// item
struct Item {
	char  title[MAX_ITEM_SIZE];
	char  username[MAX_ITEM_SIZE];
	char  password[MAX_ITEM_SIZE];
};
typedef struct Item item_t;

// wallet
struct Wallet {
	item_t items[MAX_ITEMS];
	size_t size;
	char master_password[MAX_ITEM_SIZE];
};
typedef struct Wallet wallet_t;



#endif // WALLET_H_