#include "l4dtoolz_mm.h"
#ifdef WIN32
#include "signature_win32.h"
#else
#include "signature_linux.h"
#endif

l4dtoolz g_l4dtoolz;
IVEngineServer *engine = NULL;
ICvar *icvar = NULL;

void *l4dtoolz::info_players_ptr = NULL;
void *l4dtoolz::info_players_org = NULL;
void *l4dtoolz::lobby_match_ptr = NULL;
void *l4dtoolz::lobby_match_org = NULL;
void *l4dtoolz::cookie_ptr = NULL;
void *l4dtoolz::sv_ptr = NULL;
void *l4dtoolz::maxslots_ptr = NULL;
void *l4dtoolz::maxslots_org = NULL;
void *l4dtoolz::slots_check_ptr = NULL;
void *l4dtoolz::slots_check_org = NULL;
void *l4dtoolz::players_running_ptr = NULL;
void *l4dtoolz::players_running_org = NULL;
void *l4dtoolz::players_range_ptr = NULL;
void *l4dtoolz::players_range_org = NULL;

ConVar sv_maxplayers("sv_maxplayers", "-1", 0, "Max human players", true, -1, true, 32, l4dtoolz::OnChangeMaxplayers);

void l4dtoolz::OnChangeMaxplayers(IConVar *var, const char *pOldValue, float flOldValue){
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(!slots_check_ptr || !maxslots_ptr || !info_players_ptr){
		Msg("sv_maxplayers init error\n");
		return;
	}
	if(new_value>=0){
		maxslots_new[4] = info_players_new[3] = (unsigned char)new_value;
		if(lobby_match_ptr){
			lobby_match_new[2] = (unsigned char)new_value;
			write_signature(lobby_match_ptr, lobby_match_new);
		}else{
			Msg("lobby_match_ptr init error\n");
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

CON_COMMAND(sv_unreserved, "Remove lobby reservation"){
	void *cookie = l4dtoolz::GetCookie();
	if(!cookie){
		Msg("cookie_ptr init error\n");
		return;
	}
	((void (*)(void *, unsigned long long, const char *))cookie)(l4dtoolz::GetSv(), 0, "Unreserved by L4DToolZ");
	engine->ServerCommand("sv_allow_lobby_connect_only 0\n");
}

class BaseAccessor:public IConCommandBaseAccessor{
public:
	bool RegisterConCommandBase(ConCommandBase *pCommandBase){
		return META_REGCVAR(pCommandBase);
	}
} s_BaseAccessor;

PLUGIN_EXPOSE(l4dtoolz, g_l4dtoolz);

bool l4dtoolz::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late){
	PLUGIN_SAVEVARS();
	GET_V_IFACE_CURRENT(GetEngineFactory, engine, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
	GET_V_IFACE_CURRENT(GetEngineFactory, icvar, ICvar, CVAR_INTERFACE_VERSION);
#if SOURCE_ENGINE >= SE_ORANGEBOX
	g_pCVar = icvar;
	ConVar_Register(0, &s_BaseAccessor);
#else
	ConCommandBaseMgr::OneTimeInit(&s_BaseAccessor);
#endif
	struct base_addr_t base_addr;
	base_addr.addr = NULL;
	base_addr.len = 0;

	find_base_from_list(srv_dll, &base_addr);
	if(!info_players_ptr){
		info_players_ptr = find_signature(info_players, &base_addr, 0);
		get_original_signature(info_players_ptr, info_players_new, info_players_org);
	}

	find_base_from_list(mat_dll, &base_addr);
	if(!lobby_match_ptr){
		lobby_match_ptr = find_signature(lobby_match, &base_addr, 1);
		get_original_signature(lobby_match_ptr, lobby_match_new, lobby_match_org);
	}

	if(!sv_ptr){
	#ifdef WIN32
		unsigned int off = *(unsigned int *)(get_offset(0, &IVEngineServer::GetPlayerInfo)+4);
	#else
		unsigned int off = get_offset(0, &IVEngineServer::GetPlayerInfo)-1;
	#endif
		sv_ptr = *(void **)(*(unsigned int *)(*(unsigned int *)engine+off)+sv_off);
	}
	find_base_from_list(eng_dll, &base_addr);
	if(sv_ptr && !cookie_ptr) cookie_ptr = (void *)((unsigned int)find_signature(cookie, &base_addr, 0)+cookie_off);
	if(!maxslots_ptr){
		maxslots_ptr = find_signature(maxslots, &base_addr, 0);
		get_original_signature(maxslots_ptr, maxslots_new, maxslots_org);
	}
	if(!slots_check_ptr){
	#ifdef WIN32
		slots_check_ptr = maxslots_ptr;
	#else
		slots_check_ptr = find_signature(slots_check, &base_addr, 0);
	#endif
		get_original_signature(slots_check_ptr, slots_check_new, slots_check_org);
	}
	if(!players_running_ptr){
		if((players_running_ptr = find_signature(players_running, &base_addr, 0))){
			if((players_range_ptr = find_signature(players_range, &base_addr, 0))){
				get_original_signature(players_running_ptr, players_running_new, players_running_org);
				write_signature(players_running_ptr, players_running_new);
				get_original_signature(players_range_ptr, players_range_new, players_range_org);
				write_signature(players_range_ptr, players_range_new);
			}
		}
	}
	return true;
}

bool l4dtoolz::Unload(char *error, size_t maxlen){
	safe_free(info_players_ptr, info_players_org);
	safe_free(lobby_match_ptr, lobby_match_org);
	safe_free(maxslots_ptr, maxslots_org);
	safe_free(slots_check_ptr, slots_check_org);
	safe_free(players_running_ptr, players_running_org);
	safe_free(players_range_ptr, players_range_org);
	return true;
}

const char *l4dtoolz::GetAuthor(){
	return "Ivailosp, lakwsh";
}

const char *l4dtoolz::GetName(){
	return "L4DToolZ";
}

const char *l4dtoolz::GetDescription(){
	return "";
}

const char *l4dtoolz::GetURL(){
	return "https://github.com/lakwsh/l4dtoolz";
}

const char *l4dtoolz::GetLicense(){
	return "";
}

const char *l4dtoolz::GetVersion(){
	return "1.0.2.2";
}

const char *l4dtoolz::GetDate(){
	return __DATE__;
}

const char *l4dtoolz::GetLogTag(){
	return "L4DToolZ";
}
