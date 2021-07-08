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
#include <sys/stat.h>
#include <fcntl.h>
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
void *real(void *handle, const char *symbol){
	typedef Elf32_Ehdr ElfHeader;
	typedef Elf32_Shdr ElfSHeader;
	typedef Elf32_Sym ElfSymbol;
	#define ELF_SYM_TYPE ELF32_ST_TYPE

	struct link_map *dlmap = (struct link_map *)handle;
	int dlfile = open(dlmap->l_name, O_RDONLY);
	struct stat dlstat;
	if(dlfile==-1 || fstat(dlfile, &dlstat)==-1){
		close(dlfile);
		return NULL;
	}

	/* Map library file into memory */
	ElfHeader *file_hdr = (ElfHeader *)mmap(NULL, dlstat.st_size, PROT_READ, MAP_PRIVATE, dlfile, 0);
	close(dlfile);
	if(file_hdr==MAP_FAILED) return NULL;
	if(!file_hdr->e_shoff || file_hdr->e_shstrndx==SHN_UNDEF){
		munmap(file_hdr, dlstat.st_size);
		return NULL;
	}

	uintptr_t map_base = (uintptr_t)file_hdr;
	ElfSHeader *sections = (ElfSHeader *)(map_base+file_hdr->e_shoff);
	/* Get ELF section header string table */
	ElfSHeader *shstrtab_hdr = &sections[file_hdr->e_shstrndx];
	const char *shstrtab = (const char *)(map_base+shstrtab_hdr->sh_offset);

	/* Iterate sections while looking for ELF symbol table and string table */
	ElfSHeader *symtab_hdr = NULL, *strtab_hdr = NULL;
	for(uint16_t i = 0; i<file_hdr->e_shnum; i++){
		ElfSHeader &hdr = sections[i];
		const char *section_name = shstrtab+hdr.sh_name;

		if(!strcmp(section_name, ".symtab")) symtab_hdr = &hdr;
		else if(!strcmp(section_name, ".strtab")) strtab_hdr = &hdr;
	}
	if(!symtab_hdr || !strtab_hdr){
		munmap(file_hdr, dlstat.st_size);
		return NULL;
	}

	ElfSymbol *symtab = (ElfSymbol *)(map_base+symtab_hdr->sh_offset);
	const char *strtab = (const char *)(map_base+strtab_hdr->sh_offset);
	void *result = NULL;
	/* Iterate symbol table starting from the position we were at last time */
	for(uint32_t i = 0; i<symtab_hdr->sh_size/symtab_hdr->sh_entsize; i++){
		ElfSymbol &sym = symtab[i];
		unsigned char sym_type = ELF_SYM_TYPE(sym.st_info);
		const char *sym_name = strtab+sym.st_name;
		/* Skip symbols that are undefined or do not refer to functions or objects */
		if(sym.st_shndx==SHN_UNDEF || (sym_type!=STT_FUNC && sym_type!=STT_OBJECT)) continue;
		if(!strcmp(symbol, sym_name)){
			result = (void *)(dlmap->l_addr+sym.st_value);
			break;
		}
	}

	munmap(file_hdr, dlstat.st_size);
	return result;
}
#endif

void *resolveSymbol(void *addr, const char *symbol){
#ifdef WIN32
	return GetProcAddress((HMODULE)addr, symbol);
#else
	void *result = NULL;
	Dl_info info;
	if(dladdr(addr, &info)){
		void *handle = dlopen(info.dli_fname, RTLD_NOW);
		if(handle){
			//result = dlsym(handle, symbol);
			result = real(handle, symbol);
			dlclose(handle);
		}
	}
	return result;
#endif
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

void safe_free(void *addr, void *&signature){
	if(!signature) return;
	write_signature(addr, signature);
	free(signature);
	signature = NULL;
}
