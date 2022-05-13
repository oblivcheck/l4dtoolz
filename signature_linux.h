#ifndef _INCLUDE_L4D2_SIGNATURE_LINUX_
#define _INCLUDE_L4D2_SIGNATURE_LINUX_

const char *srv_dll[] = {"server_srv.so", 0};
const char *eng_dll[] = {"engine_srv.so", 0};
const char *mat_dll[] = {"matchmaking_ds_srv.so", 0};

const char *info_players = "\x08\xC9\x3C\x01\x19\xC0\x83\xE0\xFC";
unsigned char info_players_new[] = {0x06, 0xF5, 0xB8, '*', 0x00, 0x00, 0x00, 0xC3};

const char *lobby_match = "\x06\x55\xB8\x08\x00\x00\x00";
unsigned char lobby_match_new[] = {0x01, 0x02, '*'};

#define sv_off		0x17
#define cookie_off	0x24
#define state_off	0x0A
#define setmax_idx	0x26
#define steam3_idx	0x41
#define steam3_off	0x0D

const char *maxslots = "\x08\x3B\x9F\x7C\x01\x00\x00\x0F\x8E";
unsigned char maxslots_new[] = {0x06, 0x00, 0x83, 0xFB, '*', 0x90, 0x90, 0x90};

const char *slots_check = "\x07\xFF\x50\x70\x84\xC0\x0F\x84";
const char *slots_check_new = "\x06\x0B\xBE\x01\x00\x00\x00\x90";

const char *range_check = "\x0C\x8B\x83\xC3\xC3\x00\x00\x39\xD0\x7C\x0B\x8B\x83";
const char *range_check_new = "\x06\x00\xB8\x20\x00\x00\x00\x90";

const char *rate_check = "\x09\xF3\x0F\x10\x45\x0C\x0F\x2F\xC8\x72";
const char *rate_check_new = "\x01\x08\xEB";
unsigned char rate_set_new[] = {0x04, 0xFA, '*', '*', '*', '*'};
#endif //_INCLUDE_L4D2_SIGNATURE_LINUX_
