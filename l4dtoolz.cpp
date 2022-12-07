#include "l4dtoolz.h"
#ifdef WIN32
#include "signature_win32.h"
#else
#include "signature_linux.h"
#endif

l4dtoolz g_l4dtoolz;
EXPOSE_SINGLE_INTERFACE_GLOBALVAR(l4dtoolz, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS, g_l4dtoolz);

IVEngineServer *engine = NULL;
ICvar *icvar = NULL;

uint *l4dtoolz::tickint_ptr = NULL;
void *l4dtoolz::tickint_org = NULL;
void *l4dtoolz::sv_ptr = NULL;
uint *l4dtoolz::slots_ptr = NULL;
uint64 *l4dtoolz::cookie_ptr = NULL;
uint *l4dtoolz::maxcl_ptr = NULL;
uint *l4dtoolz::steam3_ptr = NULL;
void *l4dtoolz::authreq_ptr = NULL;
void *l4dtoolz::authreq_org = NULL;
uint *l4dtoolz::authrsp_ptr = NULL;
uint l4dtoolz::authrsp_org = 0;
void *l4dtoolz::info_players_ptr = NULL;
void *l4dtoolz::info_players_org = NULL;
void *l4dtoolz::lobby_match_ptr = NULL;
void *l4dtoolz::lobby_match_org = NULL;
void *l4dtoolz::rate_check_ptr = NULL;
void *l4dtoolz::rate_check_org = NULL;
void *l4dtoolz::rate_set_org = NULL;
void *l4dtoolz::lobby_req_ptr = NULL;
void *l4dtoolz::lobby_req_org = NULL;

ConVar sv_maxplayers("sv_maxplayers", "-1", 0, "Max human players", true, -1, true, 31, l4dtoolz::OnChangeMax);
void l4dtoolz::OnChangeMax(IConVar *var, const char *pOldValue, float flOldValue){
	if(!slots_ptr || !info_players_ptr){
		var->SetValue(-1);
		Msg("[L4DToolZ] sv_maxplayers init error\n");
		return;
	}
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(new_value<0){
		write_signature(info_players_ptr, info_players_org);
		if(lobby_match_ptr) write_signature(lobby_match_ptr, lobby_match_org);
		return;
	}
	*slots_ptr = new_value;
	info_players_new[3] = lobby_match_new[2] = (unsigned char)new_value;
	if(lobby_match_ptr) write_signature(lobby_match_ptr, lobby_match_new);
	else Msg("[L4DToolZ] lobby_match init error\n");
	write_signature(info_players_ptr, info_players_new);
}

ConVar sv_lobby_cookie("sv_lobby_cookie", "0", 0);
void l4dtoolz::Cookie_f(const CCommand &args){
	if(!cookie_ptr){
		Msg("[L4DToolZ] sv_cookie init error\n");
		return;
	}
	if(*cookie_ptr){
		char buf[20];
		snprintf(buf, sizeof(buf), "%llu", *cookie_ptr);
		sv_lobby_cookie.SetValue(buf);
	}
	if(args.ArgC()!=2){
		engine->ServerCommand("sv_lobby_cookie\n");
		return;
	}
	uint64 val = atoll(args[1]);
	icvar->FindVar("sv_hosting_lobby")->SetValue(val!=0);
	icvar->FindVar("sv_allow_lobby_connect_only")->SetValue(val!=0);
	*cookie_ptr = val;
}
ConCommand cookie("sv_cookie", l4dtoolz::Cookie_f, "Lobby reservation cookie");

ConVar sv_setmax("sv_setmax", "18", 0, "Max clients", true, 18, true, 32, l4dtoolz::OnSetMaxCl);
void l4dtoolz::OnSetMaxCl(IConVar *var, const char *pOldValue, float flOldValue){
	if(!maxcl_ptr){
		Msg("[L4DToolZ] sv_setmax init error\n");
		return;
	}
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	*maxcl_ptr = new_value;
	Msg("[L4DToolZ] maxplayers set to %d\n", new_value);
}

void l4dtoolz::LevelInit(char const *){
	if(!slots_ptr) return;
	int slots = sv_maxplayers.GetInt();
	if(slots>=0) *slots_ptr = slots;
}

#ifdef WIN32
int l4dtoolz::PreAuth(const void *, int, uint64 steamID){
#else
int l4dtoolz::PreAuth(void *, const void *, int, uint64 steamID){
#endif
	if(!steamID){
		Msg("[L4DToolZ] invalid steamID.\n");
		return 1;
	}
	Msg("[L4DToolZ] %llu connected.\n", steamID);
	return 0;
}

ConVar sv_steam_bypass("sv_steam_bypass", "0", 0, "Bypass steam validation", true, 0, true, 1, l4dtoolz::OnBypassAuth);
void l4dtoolz::OnBypassAuth(IConVar *var, const char *pOldValue, float flOldValue){
	if(!steam3_ptr){
	err_bypass:
		var->SetValue(0);
		Msg("[L4DToolZ] sv_steam_bypass init error\n");
		return;
	}
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	unsigned char authreq_new[6] = {0x04, 0x00};
	if(!authreq_ptr){
		auto gsv = (uint **)steam3_ptr[1];
		if(!gsv) goto err_bypass;
		authreq_ptr = &gsv[0][authreq_idx];
		*(uint *)&authreq_new[2] = (uint)&l4dtoolz::PreAuth;
		read_signature(authreq_ptr, authreq_new, authreq_org);
	}
	if(new_value) write_signature(authreq_ptr, authreq_new);
	else write_signature(authreq_ptr, authreq_org);
}

PLUGIN_RESULT l4dtoolz::ClientConnect(bool *bAllowConnect, edict_t *pEntity, const char *, const char *, char *, int){
	if(sv_steam_bypass.GetInt()!=1) return PLUGIN_CONTINUE;
	const CSteamID *steamID = engine->GetClientSteamID(pEntity);
	if(!steamID){
		Msg("[L4DToolZ] invalid steamID.\n");
	reject:
		*bAllowConnect = false;
		return PLUGIN_STOP;
	}
	ValidateAuthTicketResponse_t rsp = {*(uint64 *)steamID};
#ifdef WIN32
	((void (__thiscall *)(void *, void *))authrsp_org)(steam3_ptr, &rsp);
#else
	((void (*)(void *, void *))authrsp_org)(steam3_ptr, &rsp);
#endif
	if(engine->GetPlayerUserId(pEntity)==-1) goto reject;
	Msg("[L4DToolZ] %llu validated.\n", rsp.id);
	return PLUGIN_CONTINUE;
}

#ifdef WIN32
void l4dtoolz::PostAuth(ValidateAuthTicketResponse_t *rsp){
#else
void l4dtoolz::PostAuth(void *, ValidateAuthTicketResponse_t *rsp){
#endif
	if(rsp->id!=rsp->owner){
		rsp->code = 2;
		Msg("[L4DToolZ] %llu using family sharing, owner: %llu.\n", rsp->id, rsp->owner);
	}
#ifdef WIN32
	__asm{
		leave
		mov ecx, steam3_ptr
		jmp authrsp_org
	}
#else
	((void (*)(void *, void *))authrsp_org)(steam3_ptr, rsp);
#endif
}

ConVar sv_anti_sharing("sv_anti_sharing", "0", 0, "No family sharing", true, 0, true, 1, l4dtoolz::OnAntiSharing);
void l4dtoolz::OnAntiSharing(IConVar *var, const char *pOldValue, float flOldValue){
	if(!authrsp_ptr){
		var->SetValue(0);
		Msg("[L4DToolZ] sv_anti_sharing init error\n");
		return;
	}
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(new_value) *authrsp_ptr = (uint)&l4dtoolz::PostAuth;
	else *authrsp_ptr = authrsp_org;
}

ConVar sv_force_unreserved("sv_force_unreserved", "0", 0, "Disallow lobby reservation", true, 0, true, 1, l4dtoolz::OnForceUnreserved);
void l4dtoolz::OnForceUnreserved(IConVar *var, const char *pOldValue, float flOldValue){
	if(!lobby_req_ptr){
		var->SetValue(0);
		Msg("[L4DToolZ] sv_force_unreserved init error\n");
		return;
	}
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(new_value){
		write_signature(lobby_req_ptr, lobby_req_new);
		icvar->FindVar("sv_allow_lobby_connect_only")->SetValue(0);
		return;
	}
	write_signature(lobby_req_ptr, lobby_req_org);
}

int GetTick(){
	static int tick = CommandLine()->ParmValue("-tickrate", 30);
	return tick;
}

float GetTickInterval(){
	static float tickint = 1.0/GetTick();
	return tickint;
}

bool l4dtoolz::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory){
	engine = (IVEngineServer *)interfaceFactory(INTERFACEVERSION_VENGINESERVER, NULL);
	icvar = (ICvar *)interfaceFactory(CVAR_INTERFACE_VERSION, NULL);

	ConnectTier1Libraries(&interfaceFactory, 1);
	ConVar_Register(0);

	mem_info base = {NULL, 0};

	find_base_from_list(srv_dll, &base);
	if(!info_players_ptr){
		info_players_ptr = find_signature(info_players, &base);
		read_signature(info_players_ptr, info_players_new, info_players_org);
	}

	find_base_from_list(mat_dll, &base);
	if(!lobby_match_ptr){
		lobby_match_ptr = find_signature(lobby_match, &base, true);
		read_signature(lobby_match_ptr, lobby_match_new, lobby_match_org);
	}

	find_base_from_list(eng_dll, &base);
	if(!sv_ptr){
		uint **sv = *(uint ***)(((uint **)engine)[0][0x80]+sv_off);
		if(!CHKPTR(sv)) goto err_sv;
		sv_ptr = sv;
		slots_ptr = (uint *)&sv[slots_idx];
		cookie_ptr = (uint64 *)&sv[cookie_idx];
		maxcl_ptr = (uint *)&sv[maxcl_idx];
		auto sfunc = (uint *(*)(void))READCALL(sv[0][steam3_idx]+steam3_off);
		if(CHKPTR(sfunc)){
			steam3_ptr = sfunc(); // conn
			authrsp_ptr = &steam3_ptr[authrsp_idx];
			authrsp_org = *authrsp_ptr;
		}
		lobby_req_ptr = (void *)sv[0][lobbyreq_idx];
		read_signature(lobby_req_ptr, lobby_req_new, lobby_req_org);
	}
err_sv:

	int tick = GetTick();
	if(tick==30) return true;
	Msg("[L4DToolZ] tickrate: %d\n", tick);
	if(!tickint_ptr){
		auto game = (uint **)gameServerFactory(INTERFACEVERSION_SERVERGAMEDLL, NULL);
		tickint_ptr = &game[0][tickint_idx];
		unsigned char tickint_new[6] = {0x04, 0x00};
		*(uint *)&tickint_new[2] = (uint)&GetTickInterval;
		read_signature(tickint_ptr, tickint_new, tickint_org);
		write_signature(tickint_ptr, tickint_new);
	}
	if(!rate_check_ptr){
		rate_check_ptr = find_signature(rate_check, &base);
		read_signature(rate_check_ptr, rate_check_new, rate_check_org);
		write_signature(rate_check_ptr, rate_check_new);
		read_signature(rate_check_ptr, rate_set_new, rate_set_org);
	#ifdef WIN32
		*(uint *)&rate_set_new[3] = tick*1000;
	#else
		*(uint *)&rate_set_new[2] = tick*1000;
	#endif
		write_signature(rate_check_ptr, rate_set_new); // sd
		((uint *)icvar->FindVar("net_splitpacket_maxrate"))[15] = false; // m_bHasMax
	}
	return true;
}

void l4dtoolz::Unload(){
	ConVar_Unregister();
	DisconnectTier1Libraries();

	if(authrsp_ptr) *authrsp_ptr = authrsp_org;
	free_signature(info_players_ptr, info_players_org);
	free_signature(lobby_match_ptr, lobby_match_org);
	free_signature(rate_check_ptr, rate_check_org);
	free_signature(rate_check_ptr, rate_set_org);
	free_signature(authreq_ptr, authreq_org);
	free_signature(tickint_ptr, tickint_org);
	free_signature(lobby_req_ptr, lobby_req_org);
}
