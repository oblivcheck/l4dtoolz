#ifndef _INCLUDE_L4D2_SIGNATURE_LINUX_
#define _INCLUDE_L4D2_SIGNATURE_LINUX_

const char *srv_dll[] = {"server_srv.so", 0};
const char *eng_dll[] = {"engine_srv.so", 0};
const char *mat_dll[] = {"matchmaking_ds_srv.so", 0};

const char *info_players = "\x08\xC9\x3C\x01\x19\xC0\x83\xE0\xFC";
unsigned char info_players_new[] = {0x06, 0xF5, 0xB8, 0x3C, 0x00, 0x00, 0x00, 0xC3};

const char *lobby_match = "\x09\x55\xB8\x08\x00\x00\x00\x89\xE5\x5D";
unsigned char lobby_match_new[] = {0x01, 0x02, 0xC3};

const char *reserved = "\x0B\x8B\x55\x10\x89\x7D\xFC\x8B\x75\xC3\x8B\x8B";
const char *reserved_new = "\x01\xED\xC3";

const char *maxslots = "\x0A\xFF\x50\xC3\x29\xC6\x03\x75\xC3\x3B\xB3";
unsigned char maxslots_new[] = {0x06, 0x08, 0x83, 0xFE, 0x3C, 0x90, 0x90, 0x90};

const char *slots_check = "\x0A\x84\xC0\x0F\x84\xC3\xC3\xC3\xC3\x8B\xB3";
const char *slots_check_new = "\x06\x08\xBE\x01\x00\x00\x00\x90";

const char *players_range = "\x0C\x8B\x83\xC3\xC3\x00\x00\x39\xD0\x7C\x0B\x8B\x83";
const char *players_range_new = "\x06\x00\xB8\x40\x00\x00\x00\x90";

const char *players_running = "\x08\x7F\xC3\x8B\x80\xC3\xC3\x00\x00";
const char *players_running_new = "\x02\x00\x90\x90";

const char *allow_cheats = "\x0D\xFF\x50\xC3\x84\xC0\x0F\x85\xC3\x00\x00\x00\x8B\x03";
const char *allow_cheats_new = "\x03\x00\x30\xC0\x90";
#endif //_INCLUDE_L4D2_SIGNATURE_LINUX_
