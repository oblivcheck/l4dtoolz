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
uint l4dtoolz::sv_ptr = 0;
uint l4dtoolz::cookie_ptr = 0;
float *l4dtoolz::tick_ptr = 0;
uint l4dtoolz::setmax_ptr = 0;
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

ConVar sv_setmax("sv_setmax", "18", 0, "Max clients", true, 18, true, 32, l4dtoolz::OnSetMax);
void l4dtoolz::OnSetMax(IConVar *var, const char *pOldValue, float flOldValue){
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
#ifdef WIN32
	auto setmax = (void (__thiscall *)(void *, int))l4dtoolz::GetSetmax();
#else
	auto setmax = (void (*)(void *, int))l4dtoolz::GetSetmax();
#endif
	if(!setmax){
		Msg("sv_setmax init error\n");
		return;
	}
	setmax(l4dtoolz::GetSv(), new_value);
}

CON_COMMAND(sv_unreserved, "Remove lobby reservation"){
	auto cookie = (void (*)(void *, unsigned long long, const char *))l4dtoolz::GetCookie();
	if(!cookie){
		Msg("cookie_ptr init error\n");
		return;
	}
	cookie(l4dtoolz::GetSv(), 0, "Unreserved by L4DToolZ");
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

	g_pCVar = icvar;
	ConVar_Register(0, &s_BaseAccessor);
	int tickrate = CommandLine()->ParmValue("-tickrate", 0);
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
	auto inf = (void *(*)(const char *, int *))get_func(base.addr, "CreateInterface");
	if(inf){
		if(!sv_ptr){
			uint **net = (uint **)inf("INETSUPPORT_001", NULL);
			if(net){
				uint func = net[0][8];
				sv_ptr = *(uint *)(func+sv_off);
				cookie_ptr = (func+cookie_off+5-1)+*(int *)(func+cookie_off);
				setmax_ptr = ((uint **)sv_ptr)[0][setmax_idx];
			}
		}
		if(tickrate && !tick_ptr){
			uint **ves = (uint **)inf("VEngineServer022", NULL);
			if(ves){
				tick_ptr = (float *)(*(uint *)(ves[0][80]+state_off)+8);
				*tick_ptr = 1.0/tickrate;
			}
		}
	}
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
	if(tickrate && !rate_check_ptr){
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
		icvar->FindVar("sv_minupdaterate")->SetValue(tickrate); // rq
		icvar->FindVar("sv_minupdaterate")->SetValue(tickrate);
		((uint *)icvar->FindVar("net_splitpacket_maxrate"))[15] = false; // m_bHasMax
	}
	return true;
}
bool l4dtoolz::Unload(char *error, size_t maxlen){
	free_signature(info_players_ptr, info_players_org);
	free_signature(lobby_match_ptr, lobby_match_org);
	free_signature(maxslots_ptr, maxslots_org);
	free_signature(slots_check_ptr, slots_check_org);
	free_signature(range_check_ptr, range_check_org);
	free_signature(rate_check_ptr, rate_check_org);
	free_signature(rate_check_ptr, rate_set_org);
	return true;
}
