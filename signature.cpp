#include <string.h>
#include <stdlib.h>
#include "signature.h"

#ifdef WIN32
#include <windows.h>
#include <TlHelp32.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#endif

#define SIGN_HEADER_LEN		2
#define SIGN_LEN_BYTE		0
#define SIGN_OFFSET_BYTE	1

void *get_func(void *addr, const char *func){
#ifdef WIN32
	return GetProcAddress((HMODULE)addr, func);
#else
	void *result = NULL;
	Dl_info info;
	if(dladdr(addr, &info)){
		void *handle = dlopen(info.dli_fname, RTLD_NOW);
		if(handle){
			result = dlsym(handle, func);
			dlclose(handle);
		}
	}
	return result;
#endif
}

#ifndef WIN32
static uint pmask = ~(sysconf(_SC_PAGESIZE)-1);

typedef struct{
	const char *name;
	mem_info *info;
} v_data;

static int callback(struct dl_phdr_info *info, size_t size, void *data){
	v_data *d = (v_data *)data;
	if(!info->dlpi_name || !strstr(info->dlpi_name, d->name)) return 0;
	d->info->addr = (void *)info->dlpi_addr;
	d->info->len = info->dlpi_phdr[0].p_filesz; // p_type=1 p_offset=0
	return 1;
}
#endif

static bool find_base(const char *name, mem_info *base_addr){
#ifdef WIN32
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if(hModuleSnap==INVALID_HANDLE_VALUE) return false;
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	while(Module32Next(hModuleSnap, &me32)){ // srcds
		if(!strcmp(me32.szModule, name)){
			base_addr->addr = me32.modBaseAddr;
			base_addr->len = me32.modBaseSize;
			CloseHandle(hModuleSnap);
			return true;
		}
	}
	CloseHandle(hModuleSnap);
#else
	v_data vdata = {name, base_addr};
	if(dl_iterate_phdr(callback, &vdata)) return true;
#endif
	return false;
}

void find_base_from_list(const char *name[], mem_info *base_addr){
	base_addr->addr = NULL;
	base_addr->len = 0;
	if(!name) return;
	int i = 0;
	while(name[i] && !find_base(name[i], base_addr)) i++;
}

void *find_signature(const char *mask, mem_info *base_addr, bool pure){
	if(!base_addr->addr) return NULL;
	char *pBase = (char *)base_addr->addr;
	uint len = mask[SIGN_LEN_BYTE];
	char *pEnd = pBase+base_addr->len-(int)len;
#ifndef WIN32
	char *pa_addr = (char *)((uint)pBase&pmask);
	uint size = pEnd-pa_addr;
	mlock(pa_addr, size);
#endif
	while(pBase<pEnd){
		uint i = 1; // skip len byte
		for(char *tmp = pBase; i<=len; ++i, ++tmp){
			if(!pure && mask[i]=='\xC3') continue;
			if(mask[i]!=*tmp) break;
		}
		if(--i==len){
		#ifndef WIN32
			munlock(pa_addr, size);
		#endif
			return pBase;
		}
		pBase++;
	}
#ifndef WIN32
	munlock(pa_addr, size);
#endif
	return NULL;
}

#ifndef WIN32
static inline void lock_region(void *addr, uint len, bool lock){
	void *pa_addr = (void *)((uint)addr&pmask);
	uint size = (uint)addr-(uint)pa_addr+len;
	if(lock){
		mlock(pa_addr, size);
		mprotect(pa_addr, size, PROT_READ|PROT_WRITE|PROT_EXEC);
	}else{
		mprotect(pa_addr, size, PROT_READ|PROT_EXEC);
		munlock(pa_addr, size);
	}
}
#endif

static void read_signature(void *addr, void *sign){
	uint sign_len = ((unsigned char *)sign)[SIGN_LEN_BYTE];
	void *src = (void *)((uint)addr+((char *)sign)[SIGN_OFFSET_BYTE]);
	void *dst = (void *)((uint)sign+SIGN_HEADER_LEN);
#ifdef WIN32
	memcpy(dst, src, sign_len);
#else
	lock_region(src, sign_len, true);
	memcpy(dst, src, sign_len);
	lock_region(src, sign_len, false);
#endif
}

void get_original_signature(void *addr, const void *new_sign, void *&org_sign){
	if(!addr) return;
	org_sign = malloc(((unsigned char *)new_sign)[SIGN_LEN_BYTE]+SIGN_HEADER_LEN);
	if(!org_sign) return;
	memcpy(org_sign, new_sign, SIGN_HEADER_LEN);
	read_signature(addr, org_sign);
}

void write_signature(void *addr, const void *sign){
	if(!addr || !sign) return;
	uint sign_len = ((unsigned char *)sign)[SIGN_LEN_BYTE];
	void *src = (void *)((uint)sign+SIGN_HEADER_LEN);
	void *dst = (void *)((uint)addr+((char *)sign)[SIGN_OFFSET_BYTE]);
#ifdef WIN32
	HANDLE h_process = GetCurrentProcess();
	WriteProcessMemory(h_process, dst, src, sign_len, NULL); // builtin
	CloseHandle(h_process);
#else
	lock_region(dst, sign_len, true);
	memcpy(dst, src, sign_len);
	lock_region(dst, sign_len, false);
#endif
}

void safe_free(void *addr, void *&sign){
	write_signature(addr, sign);
	free(sign);
	sign = NULL;
}
