#ifndef _INCLUDE_SIGNATURE_
#define _INCLUDE_SIGNATURE_

typedef unsigned int uint;
struct base_addr_t{
	void *addr;
	uint len;
};

void *find_signature(const char *mask, struct base_addr_t *base_addr, int pure);
void *resolveSymbol(void *addr, const char *symbol);
void find_base_from_list(const char *name[], struct base_addr_t *base_addr);
void write_signature(void *addr, const void *signature);
void get_original_signature(void *offset, const void *new_sig, void *&org_sig);
void safe_free(void *addr, void *&signature);
uint get_offset(int s, ...);
#endif //_INCLUDE_SIGNATURE_
