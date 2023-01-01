#ifndef _INCLUDE_L4D2_SIGNATURE_LINUX_
#define _INCLUDE_L4D2_SIGNATURE_LINUX_

const char *srv_dll[] = {"server_srv.so", 0};
const char *eng_dll[] = {"engine_srv.so", 0};
const char *mat_dll[] = {"matchmaking_ds_srv.so", 0};

const char *info_players = "\x08\xC9\x3C\x01\x19\xC0\x83\xE0\xFC";
unsigned char info_players_new[] = {0x06, 0xF5, 0xB8, '*', 0x00, 0x00, 0x00, 0xC3};

const char *lobby_match = "\x06\x55\xB8\x08\x00\x00\x00";
unsigned char lobby_match_new[] = {0x01, 0x02, '*'};

#define tickint_idx	0x09 // rodata
#define sv_off		0x06 // bss
#define slots_idx	0x5F // sv
#define cookie_idx	0x5B
#define maxcl_idx	0x41
#define steam3_idx	0x41
#define steam3_off	0x0D
#define authreq_idx	0x1A // rodata (?)
#define authrsp_idx	0x24 // bss
#define lobbyreq_idx	0x3E // rodata

const char *rate_check = "\x09\xF3\x0F\x10\x45\x0C\x0F\x2F\xC8\x72";
const char *rate_check_new = "\x01\x08\xEB";
unsigned char rate_set_new[] = {0x04, 0xFA, '*', '*', '*', '*'};

const char *lobby_req_new = "\x01\x00\xC3";

const char *vomit_fix = "\x0D\xA1\xC3\xC3\xC3\xC3\xF3\x0F\x10\x40\x10\xF3\x0F\x59";
unsigned char vomit_fix_new[] = {0x05, 0x00, 0xB8, '*', '*', '*', '*'};
#endif // _INCLUDE_L4D2_SIGNATURE_LINUX_
