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
#define sv_off		0x08
#define slots_idx	0x60
#define cookie_idx	0x5C
#define maxcl_idx	0x41
#define steam3_idx	0x40
#define steam3_off	0x0D
#define authreq_idx	0x1A
#define authrsp_idx	0x20
#define lobbyreq_idx	0x3D

const char *rate_check = "\x0D\x0F\x2F\xC1\x76\xC3\x0F\x28\xC1\xF3\x0F\x2C\xC0\x89";
const char *rate_check_new = "\x02\x03\x90\x90";
unsigned char rate_set_new[] = {0x07, 0x05, 0xB8, '*', '*', '*', '*', 0x90, 0x90};

const char *lobby_req_new = "\x03\x00\xC2\x08\x00"; // stack balance

const char *vomit_fix = "\x10\xA1\xC3\xC3\xC3\xC3\x89\xC3\xC3\x89\xC3\xC3\xF3\x0F\x10\x40\x10";
unsigned char vomit_fix_new[] = {0x05, 0x00, 0xB8, '*', '*', '*', '*'};
#endif // _INCLUDE_L4D2_SIGNATURE_WIN32_
