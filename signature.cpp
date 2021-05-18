#include <stdio.h>
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

#ifndef WIN32
static void lock_region(void *addr, unsigned int sign_len, int sign_off, bool lock){
	unsigned int u_addr = (unsigned int)addr;
	unsigned int all_adr = (u_addr+sign_off)&~(sysconf(_SC_PAGESIZE)-1);
	unsigned int all_size = u_addr-all_adr+sign_len;
	if(lock){
		mlock((void *)all_adr, all_size);
		mprotect((void *)all_adr, all_size, PROT_READ|PROT_WRITE|PROT_EXEC);
	}else{
		munlock((void *)all_adr, all_size);
	}
}
#endif

void *find_signature(const char *mask, struct base_addr_t *base_addr, int pure){
	if(!base_addr->addr) return NULL;
	char *pBasePtr = (char *)base_addr->addr;
	char *pEndPtr = pBasePtr+base_addr->len-(int)mask[SIGN_LEN_BYTE];
#ifndef WIN32
	char *all_adr = (char *)((unsigned int)pBasePtr&~(sysconf(_SC_PAGESIZE)-1));
	unsigned int size = pEndPtr-all_adr;
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

#ifndef WIN32
struct v_data{
	const char *fname;
	void *baddr;
	unsigned int blen;
};

static int callback(struct dl_phdr_info *info, size_t size, void *data){
	if(!info->dlpi_name || !info->dlpi_name[0]) return 0;
	if(strstr(info->dlpi_name, ((struct v_data *)data)->fname)){
		if(strstr(info->dlpi_name, "metamod")==NULL){
			((struct v_data *)data)->baddr = (void *)info->dlpi_addr;
			((struct v_data *)data)->blen = 0;
			for(int i = 0; i<info->dlpi_phnum; ++i){
				((struct v_data *)data)->blen += info->dlpi_phdr[i].p_filesz;
				break;
			}
			return 1;
		}
	}
	return 0;
}
#endif

bool find_base(const char *name, struct base_addr_t *base_addr){
#ifdef WIN32
/*	HANDLE hModuleSnap = INVALID_HANDLE_VALUE; */
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if(hModuleSnap==INVALID_HANDLE_VALUE) return false;
	MODULEENTRY32 modent;
	modent.dwSize = sizeof(MODULEENTRY32);
	if(!Module32Next(hModuleSnap, &modent)){
		CloseHandle(hModuleSnap);
		return false;
	}
	do{
		if(strstr(modent.szExePath, name)){
			if(strstr(modent.szExePath, "metamod")) continue;
			base_addr->addr = modent.modBaseAddr;
			base_addr->len = modent.modBaseSize;
			CloseHandle(hModuleSnap);
			return true;
		}
	} while(Module32Next(hModuleSnap, &modent));
	CloseHandle(hModuleSnap);
#else
	struct v_data vdata;
	vdata.fname = name;
	if(dl_iterate_phdr(callback, &vdata)){
		base_addr->addr = vdata.baddr;
		base_addr->len = vdata.blen;
		return true;
	}
#endif
	base_addr->addr = NULL;
	base_addr->len = 0;
	return false;
}

void find_base_from_list(const char *name[], struct base_addr_t *base_addr){
	base_addr->addr = NULL;
	base_addr->len = 0;
	if(!name) return;
	int i = 0;
	while(name[i]!=NULL && !find_base(name[i], base_addr)) i++;
}

void write_signature(void *addr, const void *signature){
	if(!addr || !signature) return;
	unsigned int sign_len = ((unsigned char *)signature)[SIGN_LEN_BYTE];
	int sign_off = ((char *)signature)[SIGN_OFFSET_BYTE];
	void *src = (void *)((unsigned int)signature+SIGN_HEADER_LEN);
	void *dst = (void *)((unsigned int)addr+sign_off);
#ifdef WIN32
	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	WriteProcessMemory(h_process, dst, src, sign_len, NULL);
	CloseHandle(h_process);
#else
	lock_region(addr, sign_len, sign_off, true);
	memcpy(dst, src, sign_len);
	lock_region(addr, sign_len, sign_off, false);
#endif
}

void read_signature(void *addr, void *signature){
	unsigned int sign_len = ((unsigned char *)signature)[SIGN_LEN_BYTE];
	int sign_off = ((char *)signature)[SIGN_OFFSET_BYTE];
	void *src = (void *)((unsigned int)addr+sign_off);
	void *dst = (void *)((unsigned int)signature+SIGN_HEADER_LEN);
#ifdef WIN32
	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
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