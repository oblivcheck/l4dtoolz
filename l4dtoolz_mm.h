#ifndef _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
#define _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_

#include <ISmmPlugin.h>
#include "signature.h"

class l4dtoolz:public ISmmPlugin{
public:
	bool Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late);
	bool Unload(char *error, size_t maxlen);

	const char *GetAuthor();
	const char *GetName();
	const char *GetDescription();
	const char *GetURL();
	const char *GetLicense();
	const char *GetVersion();
	const char *GetDate();
	const char *GetLogTag();

	static void *GetCookie(){ return cookie_ptr; }
	static void *GetSv(){ return sv_ptr; }

	static void OnChangeMaxplayers(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnChangeCheats(IConVar *var, const char *pOldValue, float flOldValue);
private:
	static void *info_players_ptr;
	static void *info_players_org;
	static void *lobby_match_ptr;
	static void *lobby_match_org;
	static void *cookie_ptr;
	static void *sv_ptr;
	static void *maxslots_ptr;
	static void *maxslots_org;
	static void *slots_check_ptr;
	static void *slots_check_org;
	static void *players_running_ptr;
	static void *players_running_org;
	static void *players_range_ptr;
	static void *players_range_org;
	static void *allow_cheats_ptr;
	static void *allow_cheats_org;
};
extern l4dtoolz g_l4dtoolz;
PLUGIN_GLOBALVARS();
#endif //_INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
