#include "interface.h"
#include "eiface.h"
#include "tier1/tier1.h"

#include "signature.h"

#define CHKPTR(PTR)	(!((uint)(PTR)&0xF) && (void *)(PTR)>base.addr)
#define READCALL(PTR)	((PTR+5-1)+*(int *)(PTR))

#pragma pack(push, 1)
struct ValidateAuthTicketResponse_t{
	uint64 id;
	int code;
	uint64 owner;
};
#pragma pack(pop)

class l4dtoolz:public IServerPluginCallbacks{
public:
	virtual bool Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory);
	virtual void Unload();
	virtual void Pause(){ }
	virtual void UnPause(){ }
	virtual const char *GetPluginDescription(){ return "L4DToolZ v2.1.0_beta, https://github.com/lakwsh/l4dtoolz"; }
	virtual void LevelInit(char const *pMapName);
	virtual void ServerActivate(edict_t *pEdictList, int edictCount, int clientMax){ }
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

	static void Cookie_f(const CCommand &args);
	static void OnChangeMax(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnSetMaxCl(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnBypassAuth(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnAntiSharing(IConVar *var, const char *pOldValue, float flOldValue);
	static void OnForceUnreserved(IConVar *var, const char *pOldValue, float flOldValue);

#ifdef WIN32
	static int PreAuth(const void *, int, uint64);
	static void PostAuth(ValidateAuthTicketResponse_t *);
#else
	static int PreAuth(void *, const void *, int, uint64);
	static void PostAuth(void *, ValidateAuthTicketResponse_t *);
#endif
private:
	static uint *tickint_ptr;
	static void *tickint_org;
	static void *sv_ptr;
	static uint *slots_ptr;
	static uint64 *cookie_ptr;
	static uint *maxcl_ptr;
	static uint *steam3_ptr;
	static void *authreq_ptr;
	static void *authreq_org;
	static uint *authrsp_ptr;
	static uint authrsp_org;
	static void *info_players_ptr;
	static void *info_players_org;
	static void *lobby_match_ptr;
	static void *lobby_match_org;
	static void *rate_check_ptr;
	static void *rate_check_org;
	static void *rate_set_org;
	static void *lobby_req_ptr;
	static void *lobby_req_org;
};
extern l4dtoolz g_l4dtoolz;
