#include "l4dtoolz.h"
#ifdef WIN32
#include "signature_win32.h"
#else
#include "signature_linux.h"
#endif

l4dtoolz g_l4dtoolz;
EXPOSE_SINGLE_INTERFACE_GLOBALVAR(l4dtoolz, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS, g_l4dtoolz);

CreateInterfaceFn iFact = NULL;
IVEngineServer *engine = NULL;

void *l4dtoolz::postinit_ptr = NULL;
void *l4dtoolz::postinit_org = NULL;
void *l4dtoolz::sv_ptr = NULL;
void *l4dtoolz::cookie_ptr = NULL;
void *l4dtoolz::setmax_ptr = NULL;
uint *l4dtoolz::steam3_ptr = NULL;
void *l4dtoolz::authreq_ptr = NULL;
void *l4dtoolz::authreq_org = NULL;
void *l4dtoolz::authrsp_ptr = NULL;
void *l4dtoolz::info_players_ptr = NULL;
void *l4dtoolz::info_players_org = NULL;
void *l4dtoolz::lobby_match_ptr = NULL;
void *l4dtoolz::lobby_match_org = NULL;
void *l4dtoolz::maxslots_ptr = NULL;
void *l4dtoolz::maxslots_org = NULL;
void *l4dtoolz::slots_check_ptr = NULL;
void *l4dtoolz::slots_check_org = NULL;
void *l4dtoolz::range_check_ptr = NULL;
void *l4dtoolz::range_check_org = NULL;
void *l4dtoolz::rate_check_ptr = NULL;
void *l4dtoolz::rate_check_org = NULL;
void *l4dtoolz::rate_set_org = NULL;

ConVar sv_maxplayers("sv_maxplayers", "-1", 0, "Max human players", true, -1, true, 31, l4dtoolz::OnChangeMax);
void l4dtoolz::OnChangeMax(IConVar *var, const char *pOldValue, float flOldValue){
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(!slots_check_ptr || !maxslots_ptr || !info_players_ptr){
		Msg("[L4DToolZ] sv_maxplayers init error\n");
		return;
	}
	if(new_value>=0){
		maxslots_new[4] = info_players_new[3] = (unsigned char)new_value;
		if(lobby_match_ptr){
			lobby_match_new[2] = (unsigned char)new_value;
			write_signature(lobby_match_ptr, lobby_match_new);
		}else{
			Msg("[L4DToolZ] lobby_match init error\n");
		}
		write_signature(maxslots_ptr, maxslots_new);
		write_signature(slots_check_ptr, slots_check_new);
		write_signature(info_players_ptr, info_players_new);
	}else{
		write_signature(maxslots_ptr, maxslots_org);
		write_signature(slots_check_ptr, slots_check_org);
		write_signature(info_players_ptr, info_players_org);
		if(lobby_match_ptr) write_signature(lobby_match_ptr, lobby_match_org);
	}
}

ConVar sv_setmax("sv_setmax", "18", 0, "Max clients", true, 18, true, 32, l4dtoolz::OnSetMax);
void l4dtoolz::OnSetMax(IConVar *var, const char *pOldValue, float flOldValue){
	int new_value = ((ConVar *)var)->GetInt();
	if(!setmax_ptr){
		Msg("[L4DToolZ] sv_setmax init error\n");
		return;
	}
#ifdef WIN32
	((void (__thiscall *)(void *, int))setmax_ptr)(sv_ptr, new_value);
#else
	((void (*)(void *, int))setmax_ptr)(sv_ptr, new_value);
#endif
}

#ifdef WIN32
int OnAuth(const void *, int, uint64 steamID){
#else
int OnAuth(void *, const void *, int, uint64 steamID){
#endif
	if(!steamID){
		Msg("[L4DToolZ] invalid steamID.\n");
		return 1;
	}
	Msg("[L4DToolZ] %llu connected.\n", steamID);
	return 0;
}

ConVar sv_steam_bypass("sv_steam_bypass", "0", 0, "Bypass steam validation", true, 0, true, 1, l4dtoolz::OnBypass);
void l4dtoolz::OnBypass(IConVar *var, const char *pOldValue, float flOldValue){
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(!steam3_ptr){
	err_bypass:
		var->SetValue(0);
		Msg("[L4DToolZ] sv_steam_bypass init error\n");
		return;
	}
	unsigned char authreq_new[6] = {0x04, 0x00};
	if(!authreq_ptr){
		auto gsrv = (uint **)steam3_ptr[1];
		if(!gsrv) goto err_bypass;
		authreq_ptr = &gsrv[0][authreq_idx];
		authrsp_ptr = (uint *)steam3_ptr[authrsp_idx];
		*(uint *)&authreq_new[2] = (uint)&OnAuth;
		read_signature(authreq_ptr, authreq_new, authreq_org);
	}
	if(new_value) write_signature(authreq_ptr, authreq_new);
	else write_signature(authreq_ptr, authreq_org);
}

CON_COMMAND(sv_unreserved, "Remove lobby reservation"){
	auto cookie = (void (*)(void *, uint64, const char *))l4dtoolz::GetCookie();
	if(!cookie){
		Msg("[L4DToolZ] sv_unreserved init error\n");
		return;
	}
	cookie(l4dtoolz::GetSv(), 0, "Unreserved by L4DToolZ");
	engine->ServerCommand("sv_allow_lobby_connect_only 0\n");
}

PLUGIN_RESULT l4dtoolz::ClientConnect(bool *bAllowConnect, edict_t *pEntity, const char *, const char *, char *, int){
	if(sv_steam_bypass.GetInt()!=1) return PLUGIN_CONTINUE;
	const CSteamID *steamid = engine->GetClientSteamID(pEntity);
	if(!steamid){
	err_mem:
		*bAllowConnect = false;
		return PLUGIN_STOP;
	}
	void *rsp = malloc(0x14);
	if(!rsp) goto err_mem;
	memset(rsp, 0, 0x14);
	memcpy(rsp, steamid, 8);
#ifdef WIN32
	((void (__thiscall *)(void *, void *))authrsp_ptr)(steam3_ptr, rsp);
#else
	((void (*)(void *, void *))authrsp_ptr)(steam3_ptr, rsp);
#endif
	Msg("[L4DToolZ] %llu validated.\n", *(uint64 *)rsp);
	free(rsp);
	return PLUGIN_CONTINUE;
}

void l4dtoolz::PostDLLInit(){
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
		uint **net = (uint **)iFact("INETSUPPORT_001", NULL);
		if(!net) goto err_sv;
		uint func = net[0][8], **p_sv = *(uint ***)(func+sv_off);
		if(!CHKPTR(p_sv)) goto err_sv;
		sv_ptr = p_sv;
		uint p1 = func+cookie_off, p2 = p_sv[0][steam3_idx]+steam3_off;
		cookie_ptr = GETPTR(READCALL(p1));
		setmax_ptr = GETPTR(p_sv[0][setmax_idx]);
		auto sfunc = (uint *(*)(void))READCALL(p2);
		if(CHKPTR(sfunc)) steam3_ptr = sfunc(); // conn
	}
err_sv:
	if(!range_check_ptr){
		range_check_ptr = find_signature(range_check, &base);
		read_signature(range_check_ptr, range_check_new, range_check_org);
		write_signature(range_check_ptr, range_check_new);
	}
	if(!maxslots_ptr){
		maxslots_ptr = find_signature(maxslots, &base);
		read_signature(maxslots_ptr, maxslots_new, maxslots_org);
	}
	if(!slots_check_ptr){
	#ifdef WIN32
		slots_check_ptr = maxslots_ptr;
	#else
		slots_check_ptr = find_signature(slots_check, &base);
	#endif
		read_signature(slots_check_ptr, slots_check_new, slots_check_org);
	}
	
#ifdef DEFAULT31SLOTS
	engine->ServerCommand("sv_setmax 31\n");
#endif

	int tickrate = CommandLine()->ParmValue("-tickrate", 0);
	if(!tickrate) return;
	*(float *)(*(uint *)(((uint **)engine)[0][80]+state_off)+8) = 1.0/tickrate;
	if(!rate_check_ptr){
		rate_check_ptr = find_signature(rate_check, &base);
		read_signature(rate_check_ptr, rate_check_new, rate_check_org);
		write_signature(rate_check_ptr, rate_check_new);
		read_signature(rate_check_ptr, rate_set_new, rate_set_org);
	#ifdef WIN32
		*(uint *)&rate_set_new[3] = tickrate*1000;
	#else
		*(uint *)&rate_set_new[2] = tickrate*1000;
	#endif
		write_signature(rate_check_ptr, rate_set_new); // sd
		ICvar *icvar = (ICvar *)iFact(CVAR_INTERFACE_VERSION, NULL);
		icvar->FindVar("sv_minupdaterate")->SetValue(tickrate); // rq
		icvar->FindVar("sv_minupdaterate")->SetValue(tickrate);
		((uint *)icvar->FindVar("net_splitpacket_maxrate"))[15] = false; // m_bHasMax
	}
}
void PostInit(){
	l4dtoolz::PostDLLInit();
	((void (*)(void))l4dtoolz::GetPostInit())();
}

bool l4dtoolz::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory){
	iFact = interfaceFactory;
	engine = (IVEngineServer *)interfaceFactory(INTERFACEVERSION_VENGINESERVER, NULL);

	ConnectTier1Libraries(&interfaceFactory, 1);
	ConVar_Register(0);

	auto game = (uint **)gameServerFactory(INTERFACEVERSION_SERVERGAMEDLL, NULL);
	postinit_ptr = &game[0][30]; // PostInit
	unsigned char postinit_new[6] = {0x04, 0x00};
	*(uint *)&postinit_new[2] = (uint)&PostInit;
	read_signature(postinit_ptr, postinit_new, postinit_org);
	write_signature(postinit_ptr, postinit_new);
	return true;
}
void l4dtoolz::Unload(){
	ConVar_Unregister();
	DisconnectTier1Libraries();

	free_signature(postinit_ptr, postinit_org);
	free_signature(info_players_ptr, info_players_org);
	free_signature(lobby_match_ptr, lobby_match_org);
	free_signature(maxslots_ptr, maxslots_org);
	free_signature(slots_check_ptr, slots_check_org);
	free_signature(range_check_ptr, range_check_org);
	free_signature(rate_check_ptr, rate_check_org);
	free_signature(rate_check_ptr, rate_set_org);
	free_signature(authreq_ptr, authreq_org);
}
