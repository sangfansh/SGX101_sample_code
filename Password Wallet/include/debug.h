#ifndef DEBUG_H_
#define DEBUG_H_


// uncomment to enable debug print
//#define ENCLAVE_DEBUG

#ifdef ENCLAVE_DEBUG
	#define DEBUG_PRINT(str) ocall_debug_print(str)
#else
	#define DEBUG_PRINT(str)
#endif

#endif // DEBUG_H_