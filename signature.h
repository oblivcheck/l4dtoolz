#ifndef _INCLUDE_SIGNATURE_
#define _INCLUDE_SIGNATURE_

struct base_addr_t{
	void *addr;
	unsigned int len;
};
void *find_signature(const char *mask, struct base_addr_t *base_addr, int pure);
bool find_base(const char *name, struct base_addr_t *base_addr);
void find_base_from_list(const char *name[], struct base_addr_t *base_addr);
void write_signature(void *addr, const void *signature);
void read_signature(void *addr, void *signature);
void get_original_signature(void *offset, const void *new_sig, void *&org_sig);
#endif //_INCLUDE_SIGNATURE_