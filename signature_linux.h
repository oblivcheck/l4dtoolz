#ifndef _INCLUDE_L4D2_SIGNATURE_LINUX_
#define _INCLUDE_L4D2_SIGNATURE_LINUX_

#define tickint_idx	0x09 // rodata
#define setrate_idx	0x1D // rodata
#define info_off	0x01
#define info_idx	0x89
#define sv_off		0x06 // bss
#define slots_idx	0x5F // sv
#define cookie_idx	0x5B
#define maxcl_idx	0x41
#define steam3_idx	0x41
#define steam3_off	0x0D
#define authreq_idx	0x1A // rodata (?)
#define authrsp_idx	0x24 // bss
#define lobbyreq_idx	0x3E // rodata

unsigned char max_player_new[] = {0x06, 0x00, 0xB8, '*', 0x00, 0x00, 0x00, 0xC3};
unsigned char lobby_req_new[] = {0x04, 0x00, '*', '*', '*', '*'};
unsigned char set_rate_new[] = {0x10, 0x00, 0xB8, '*', '*', '*', '*', 0x8B, 0x4C, 0x24, 0x04, 0x89, 0x81, 0xB0, 0x00, 0x00, 0x00, 0xC3}; // 0xB0
#endif // _INCLUDE_L4D2_SIGNATURE_LINUX_
