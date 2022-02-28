#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
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

#ifndef WIN32
static void lock_region(void *addr, uint sign_len, int sign_off, bool lock){
	uint u_addr = (uint)addr;
	uint all_adr = (u_addr+sign_off)&~(sysconf(_SC_PAGESIZE)-1);
	uint all_size = u_addr-all_adr+sign_len;
	if(lock){
		mlock((void *)all_adr, all_size);
		mprotect((void *)all_adr, all_size, PROT_READ|PROT_WRITE|PROT_EXEC);
	}else{
		munlock((void *)all_adr, all_size);
	}
}
#endif

void *find_signature(const char *mask, mem_info *base_addr, bool pure){
	if(!base_addr->addr) return NULL;
	char *pBasePtr = (char *)base_addr->addr;
	char *pEndPtr = pBasePtr+base_addr->len-(int)mask[SIGN_LEN_BYTE];
#ifndef WIN32
	char *all_adr = (char *)((uint)pBasePtr&~(sysconf(_SC_PAGESIZE)-1));
	uint size = pEndPtr-all_adr;
	mlock(all_adr, size);
#endif
	int i;
	while(pBasePtr<pEndPtr){
		char *tmp = pBasePtr;
		for(i = 1; i<=mask[SIGN_LEN_BYTE]; ++i){
			if(!pure && mask[i]=='\xC3'){
				tmp++;
				continue;
			}
			if(mask[i]!=*tmp) break;
			tmp++;
		}
		if(i-1==mask[0]){
		#ifndef WIN32
			munlock(all_adr, size);
		#endif
			return pBasePtr;
		}
		pBasePtr++;
	}
#ifndef WIN32
	munlock(all_adr, size);
#endif
	return NULL;
}

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
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if(hModuleSnap==INVALID_HANDLE_VALUE) return false;
	MODULEENTRY32 modent;
	modent.dwSize = sizeof(MODULEENTRY32);
	while(Module32Next(hModuleSnap, &modent)){
		if(strstr(modent.szExePath, name)){
			base_addr->addr = modent.modBaseAddr;
			base_addr->len = modent.modBaseSize;
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
	while(name[i]!=NULL && !find_base(name[i], base_addr)) i++;
}

void write_signature(void *addr, const void *signature){
	if(!addr || !signature) return;
	uint sign_len = ((unsigned char *)signature)[SIGN_LEN_BYTE];
	int sign_off = ((char *)signature)[SIGN_OFFSET_BYTE];
	void *src = (void *)((uint)signature+SIGN_HEADER_LEN);
	void *dst = (void *)((uint)addr+sign_off);
#ifdef WIN32
	HANDLE h_process = GetCurrentProcess();
	WriteProcessMemory(h_process, dst, src, sign_len, NULL);
	CloseHandle(h_process);
#else
	lock_region(addr, sign_len, sign_off, true);
	memcpy(dst, src, sign_len);
	lock_region(addr, sign_len, sign_off, false);
#endif
}

static void read_signature(void *addr, void *signature){
	uint sign_len = ((unsigned char *)signature)[SIGN_LEN_BYTE];
	int sign_off = ((char *)signature)[SIGN_OFFSET_BYTE];
	void *src = (void *)((uint)addr+sign_off);
	void *dst = (void *)((uint)signature+SIGN_HEADER_LEN);
#ifdef WIN32
	HANDLE h_process = GetCurrentProcess();
	ReadProcessMemory(h_process, src, dst, sign_len, NULL);
	CloseHandle(h_process);
#else
	lock_region(addr, sign_len, sign_off, true);
	memcpy(dst, src, sign_len);
	lock_region(addr, sign_len, sign_off, false);
#endif
}

void get_original_signature(void *offset, const void *new_sig, void *&org_sig){
	if(!offset) return;
	org_sig = malloc(((unsigned char *)new_sig)[SIGN_LEN_BYTE]+SIGN_HEADER_LEN);
	memcpy(org_sig, new_sig, SIGN_HEADER_LEN);
	read_signature(offset, org_sig);
}

void safe_free(void *addr, void *&signature){
	if(!signature) return;
	write_signature(addr, signature);
	free(signature);
	signature = NULL;
}
