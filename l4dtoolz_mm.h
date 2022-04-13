#ifndef _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
#define _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_

#include <ISmmPlugin.h>
#include "signature.h"

#define CHECKPTR(PTR) (PTR&0xF?NULL:(void *)PTR)
#define READCALL(PTR) ((PTR+5-1)+*(int *)PTR)

class l4dtoolz:public ISmmPlugin{
public:
	bool Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late);
	bool Unload(char *error, size_t maxlen);

	const char *GetAuthor(){ return "lakwsh, Ivailosp"; }
	const char *GetName(){ return "L4DToolZ"; }
	const char *GetDescription(){ return ""; }
	const char *GetURL(){ return "https://github.com/lakwsh/l4dtoolz"; }
	const char *GetLicense(){ return "GPLv3"; }
	const char *GetVersion(){ return "1.1.2"; }
	const char *GetDate(){ return __DATE__; }
	const char *GetLogTag(){ return "L4DToolZ"; }

	static void *GetSv(){ return sv_ptr; }
	static void *GetCookie(){ return CHECKPTR(cookie_ptr); }
	static uint GetAuthCb(){ return authcb_ptr; }
	static void OnChangeMax(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnSetMax(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnLogonKick(IConVar *var, const char *pOldValue, float flOldValue);
private:
	static void *sv_ptr;
	static uint cookie_ptr;
	static float *tick_ptr;
	static uint setmax_ptr;
	static void *steam3_ptr;
	static uint authcb_ptr;
	static void *info_players_ptr;
	static void *info_players_org;
	static void *lobby_match_ptr;
	static void *lobby_match_org;
	static void *maxslots_ptr;
	static void *maxslots_org;
	static void *slots_check_ptr;
	static void *slots_check_org;
	static void *range_check_ptr;
	static void *range_check_org;
	static void *rate_check_ptr;
	static void *rate_check_org;
	static void *rate_set_org;
};
extern l4dtoolz g_l4dtoolz;
PLUGIN_GLOBALVARS();
#endif //_INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
