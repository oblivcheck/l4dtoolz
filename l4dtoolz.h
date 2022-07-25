#include "interface.h"
#include "eiface.h"
#include "tier1/tier1.h"

#include "signature.h"

#define CHKPTR(PTR) ((uint)PTR&0xF?0:1)
#define GETPTR(PTR) (PTR&0xF?NULL:(void *)PTR)
#define READCALL(PTR) ((PTR+5-1)+*(int *)PTR)

class l4dtoolz:public IServerPluginCallbacks{
public:
	virtual bool Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory);
	virtual void Unload();
	virtual void Pause(){ }
	virtual void UnPause(){ }
	virtual const char *GetPluginDescription(){ return "L4DToolZ v2.0.0beta1, https://github.com/lakwsh/l4dtoolz"; }
	virtual void LevelInit(char const *pMapName){ }
	virtual void ServerActivate(edict_t *pEdictList, int edictCount, int clientMax);
	virtual void GameFrame(bool simulating){ }
	virtual void LevelShutdown(){ }
	virtual void ClientActive(edict_t *pEntity){ }
	virtual void ClientDisconnect(edict_t *pEntity){ }
	virtual void ClientPutInServer(edict_t *pEntity, char const *playername){ }
	virtual void SetCommandClient(int index){ }
	virtual void ClientSettingsChanged(edict_t *pEdict){ }
	virtual PLUGIN_RESULT ClientConnect(bool *bAllowConnect, edict_t *pEntity, const char *pszName, const char *pszAddress, char *reject, int maxrejectlen);
	virtual PLUGIN_RESULT ClientCommand(edict_t *pEntity, const CCommand &args){ return PLUGIN_CONTINUE; }
	virtual PLUGIN_RESULT NetworkIDValidated(const char *pszUserName, const char *pszNetworkID){ return PLUGIN_CONTINUE; }
	virtual void OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t *pPlayerEntity, EQueryCvarValueStatus eStatus, const char *pCvarName, const char *pCvarValue){ }

	static void *GetSv(){ return sv_ptr; }
	static void *GetCookie(){ return cookie_ptr; }
	static void OnChangeMax(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnSetMax(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnBypass(IConVar *var, const char *pOldValue, float flOldValue);
private:
	static int tickrate;
	static void *sv_ptr;
	static void *cookie_ptr;
	static float *tick_ptr;
	static void *setmax_ptr;
	static uint *steam3_ptr;
	static void *authreq_ptr;
	static void *authreq_org;
	static void *authrsp_ptr;
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
