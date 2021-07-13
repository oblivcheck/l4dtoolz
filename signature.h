#ifndef _INCLUDE_SIGNATURE_
#define _INCLUDE_SIGNATURE_

struct base_addr_t{
	void *addr;
	unsigned int len;
};
void *find_signature(const char *mask, struct base_addr_t *base_addr, int pure);
void *resolveSymbol(void *addr, const char *symbol);
bool find_base(const char *name, struct base_addr_t *base_addr);
void find_base_from_list(const char *name[], struct base_addr_t *base_addr);
void write_signature(void *addr, const void *signature);
void read_signature(void *addr, void *signature);
void get_original_signature(void *offset, const void *new_sig, void *&org_sig);
void safe_free(void *addr, void *&signature);
unsigned int get_offset(int s, ...);
#endif //_INCLUDE_SIGNATURE_
