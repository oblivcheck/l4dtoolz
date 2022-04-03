#ifndef _INCLUDE_L4D2_SIGNATURE_WIN32_
#define _INCLUDE_L4D2_SIGNATURE_WIN32_

const char *srv_dll[] = {"server.dll", 0};
const char *eng_dll[] = {"engine.dll", 0};
const char *mat_dll[] = {"matchmaking_ds.dll", "matchmaking.dll", 0};

const char *info_players = "\x07\xB8\x08\x00\x00\x00\x7F\x05";
unsigned char info_players_new[] = {0x06, 0xBA, 0xB8, '*', 0x00, 0x00, 0x00, 0xC3};

const char *lobby_match = "\x06\xB8\x08\x00\x00\x00\xC3";
unsigned char lobby_match_new[] = {0x01, 0x01, '*'};

#define sv_off     0x11
#define cookie_off 0x16
#define setmax_idx 0x25

const char *maxslots = "\x07\x3B\x86\x80\x01\x00\x00\x7E";
unsigned char maxslots_new[] = {0x06, 0x00, 0x83, 0xF8, '*', 0x90, 0x90, 0x90};

const char *slots_check_new = "\x02\xE2\x90\x90";

const char *range_check = "\x09\x8B\x86\x28\x02\x00\x00\x8B\x4D\x08";
const char *range_check_new = "\x06\x00\xB8\x20\x00\x00\x00\x90";
#endif //_INCLUDE_L4D2_SIGNATURE_WIN32_
