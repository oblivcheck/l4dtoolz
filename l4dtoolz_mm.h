#ifndef _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
#define _INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_

#include <ISmmPlugin.h>
#include "signature.h"

class l4dtoolz: public ISmmPlugin{
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

	static void OnChangeMaxplayers(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnChangeUnreserved(IConVar *var, const char *pOldValue, float flOldValue);
private:
	static void *max_players_connect;
	static void *max_players_server_browser;
	static void *lobby_sux_ptr;
	static void *tmp_player;
	static void *tmp_player2;
	static void *unreserved_ptr;
	static void *lobby_match_ptr;
	static void *max_players_org;
	static void *server_bplayers_org;
	static void *lobby_sux_org;
	static void *players_org;
	static void *players_org2;
	static void *unreserved_org;
	static void *lobby_match_org;

	static void safe_free(void *addr, void *&signature){
		if(!signature) return;
		write_signature(addr, signature);
		free(signature);
		signature = NULL;
	}
};
extern l4dtoolz g_l4dtoolz;
PLUGIN_GLOBALVARS();
#endif //_INCLUDE_METAMOD_SOURCE_STUB_PLUGIN_H_
