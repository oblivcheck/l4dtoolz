#ifndef _INCLUDE_L4D2_SIGNATURE_WIN32_
#define _INCLUDE_L4D2_SIGNATURE_WIN32_

const char *srv_dll[] = {"server.dll", 0};
const char *eng_dll[] = {"engine.dll", 0};
//const char *mat_dll[] = {"matchmaking_ds.dll", "matchmaking.dll", 0};

#define tickint_idx	0x09
#define setrate_idx	0x1C
#define info_off	0x02
#define info_idx	0x88
#define sv_off		0x08
#define slots_idx	0x60
#define cookie_idx	0x5C
#define maxcl_idx	0x41
#define steam3_idx	0x40
#define steam3_off	0x0D
#define authreq_idx	0x1A
#define authrsp_idx	0x20
#define lobbyreq_idx	0x3D

unsigned char max_player_new[] = {0x06, 0x00, 0xB8, '*', 0x00, 0x00, 0x00, 0xC3};
unsigned char lobby_req_new[] = {0x04, 0x00, '*', '*', '*', '*'};
unsigned char set_rate_new[] = {0x0E, 0x00, 0xB8, '*', '*', '*', '*', 0x89, 0x81, 0xB0, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00};

const char *vomit_fix = "\x10\xA1\xC3\xC3\xC3\xC3\x89\xC3\xC3\x89\xC3\xC3\xF3\x0F\x10\x40\x10";
unsigned char vomit_fix_new[] = {0x05, 0x00, 0xB8, '*', '*', '*', '*'};
#endif // _INCLUDE_L4D2_SIGNATURE_WIN32_
