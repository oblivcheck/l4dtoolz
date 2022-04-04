#ifndef _INCLUDE_SIGNATURE_
#define _INCLUDE_SIGNATURE_

typedef unsigned int uint;
typedef struct{
	void *addr;
	uint len;
} mem_info;

void *get_func(void *addr, const char *func);
void find_base_from_list(const char *name[], mem_info *base);
void *find_signature(const char *mask, mem_info *base, bool pure = false);
void read_signature(void *addr, const void *new_sign, void *&org_sign);
void write_signature(void *addr, const void *sign);
void free_signature(void *addr, void *&sign);
#endif //_INCLUDE_SIGNATURE_
