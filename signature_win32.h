#ifndef _INCLUDE_L4D2_SIGNATURE_WIN32_
#define _INCLUDE_L4D2_SIGNATURE_WIN32_

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
#endif // _INCLUDE_L4D2_SIGNATURE_WIN32_
