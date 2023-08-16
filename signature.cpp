#include <string.h>
#include <stdlib.h>
#include "signature.h"

#ifdef WIN32
#include <windows.h>
//#include <TlHelp32.h>
#else
#include <sys/mman.h>
#include <unistd.h>
//#include <link.h>

static uint pmask = ~(sysconf(_SC_PAGESIZE)-1);
#endif

#define HEADER_LEN	2
#define LEN_BYTE	0
#define OFF_BYTE	1

/*
void *get_func(void *addr, const char *func){
#ifdef WIN32
	return (void *)GetProcAddress((HMODULE)addr, func);
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
	mem_info *base;
} v_data;

static int callback(struct dl_phdr_info *info, size_t size, void *data){
	v_data *d = (v_data *)data;
	if(!info->dlpi_name || !strstr(info->dlpi_name, d->name)) return 0;
	d->base->addr = (void *)info->dlpi_addr;
	d->base->len = info->dlpi_phdr[0].p_filesz; // p_type=1 p_offset=0
	return 1;
}
#endif

static bool find_base(const char *name, mem_info *base){
#ifdef WIN32
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if(hModuleSnap==INVALID_HANDLE_VALUE) return false;
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	while(Module32Next(hModuleSnap, &me32)){ // srcds
		if(!strcmp(me32.szModule, name)){
			base->addr = me32.modBaseAddr;
			base->len = me32.modBaseSize;
			CloseHandle(hModuleSnap);
			return true;
		}
	}
	CloseHandle(hModuleSnap);
#else
	v_data vdata = {name, base};
	if(dl_iterate_phdr(callback, &vdata)) return true;
#endif
	return false;
}

void find_base_from_list(const char *name[], mem_info *base){
	base->addr = NULL;
	base->len = 0;
	if(!name) return;
	int i = 0;
	while(name[i] && !find_base(name[i], base)) i++;
}

void *find_signature(const char *mask, mem_info *base, bool pure){
	if(!base->addr) return NULL;
	char *pBase = (char *)base->addr;
	uint len = mask[LEN_BYTE];
	char *pEnd = pBase+base->len-(int)len;
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
*/

void read_signature(void *addr, const void *new_sign, void *&org_sign){
	if(!addr) return;
	uint len = ((unsigned char *)new_sign)[LEN_BYTE];
	org_sign = malloc(len+HEADER_LEN);
	if(!org_sign) return;
	memcpy(org_sign, new_sign, HEADER_LEN);
	void *src = (void *)((uint)addr+((char *)new_sign)[OFF_BYTE]);
	void *dst = (void *)((uint)org_sign+HEADER_LEN);
	memcpy(dst, src, len);
}

void write_signature(void *addr, const void *sign){
	if(!addr || !sign) return;
	uint len = ((unsigned char *)sign)[LEN_BYTE];
	void *src = (void *)((uint)sign+HEADER_LEN);
	void *dst = (void *)((uint)addr+((char *)sign)[OFF_BYTE]);
#ifdef WIN32
	DWORD old;
	VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &old); // readonly
	HANDLE h_process = GetCurrentProcess();
	WriteProcessMemory(h_process, dst, src, len, NULL); // builtin
	CloseHandle(h_process);
	VirtualProtect(dst, len, old, &old);
#else
	void *pa_addr = (void *)((uint)dst&pmask);
	uint size = (uint)dst-(uint)pa_addr+len;
	mlock(pa_addr, size);
	mprotect(pa_addr, size, PROT_READ|PROT_WRITE|PROT_EXEC);
	memcpy(dst, src, len);
	//mprotect(pa_addr, size, PROT_READ|PROT_EXEC); // restore
	munlock(pa_addr, size);
#endif
}

void free_signature(void *addr, void *&sign){
	write_signature(addr, sign);
	free(sign);
	sign = NULL;
}
