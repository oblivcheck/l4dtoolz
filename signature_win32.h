#ifndef _INCLUDE_L4D2_SIGNATURE_WIN32_
#define _INCLUDE_L4D2_SIGNATURE_WIN32_

const char *srv_dll[] = {"server.dll", 0};
const char *eng_dll[] = {"engine.dll", 0};
const char *mat_dll[] = {"matchmaking_ds.dll", "matchmaking.dll", 0};

const char *info_players = "\x07\xB8\x08\x00\x00\x00\x7F\x05";
unsigned char info_players_new[] = {0x06, 0xBA, 0xB8, '*', 0x00, 0x00, 0x00, 0xC3};

const char *lobby_match = "\x06\xB8\x08\x00\x00\x00\xC3";
unsigned char lobby_match_new[] = {0x01, 0x01, '*'};

#define tickint_idx	0x09
#define rateset_idx	0x1C
#define rate_idx	0x2C
#define sv_off		0x08
#define slots_idx	0x60
#define cookie_idx	0x5C
#define maxcl_idx	0x41
#define steam3_idx	0x40
#define steam3_off	0x0D
#define authreq_idx	0x1A
#define authrsp_idx	0x20
#define lobbyreq_idx	0x3D

unsigned char lobby_req_new[] = {0x04, 0x00, '*', '*', '*', '*'};

const char *vomit_fix = "\x10\xA1\xC3\xC3\xC3\xC3\x89\xC3\xC3\x89\xC3\xC3\xF3\x0F\x10\x40\x10";
unsigned char vomit_fix_new[] = {0x05, 0x00, 0xB8, '*', '*', '*', '*'};
#endif // _INCLUDE_L4D2_SIGNATURE_WIN32_
