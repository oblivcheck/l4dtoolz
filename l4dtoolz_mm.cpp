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
void *l4dtoolz::packet_ptr = NULL;
void *l4dtoolz::packet_org = NULL;

ConVar sv_maxplayers("sv_maxplayers", "-1", 0, "Max human players", true, -1, true, 31, l4dtoolz::OnChangeMaxplayers);
ConVar sv_antiddos("sv_antiddos", "0", 0, "Anti DDOS attack", true, 0, true, 1, l4dtoolz::OnChangePacketcheck);

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

void HookFunc(){ // top(5B) only
#ifdef WIN32
	__asm{
		call $+5 // hook
		test al, al
		jz drop
		call $+5 // restore
		jmp $+5
	drop:
		ret
	}
#else
	__asm(
		"call 0\n" // +1
		"test %al, %al\n"
		"jz drop\n"
		"call 0\n" // +9
		"jmp 0\n" // +15
	"drop:"
	);
#endif
}
bool CheckPacket(uint, int, uint *p){
	Msg("recv %.8lx %.8lx\n", p[0], p[1]);
	// blablabla...
	return true;
}
void l4dtoolz::OnChangePacketcheck(IConVar *var, const char *pOldValue, float flOldValue){
	int new_value = ((ConVar *)var)->GetInt();
	int old_value = atoi(pOldValue);
	if(new_value==old_value) return;
	if(!packet_ptr || (uint)packet_ptr&0xF){
		Msg("packet_ptr init error\n");
		return;
	}
	if(new_value) write_signature(packet_ptr, packet_new);
	else write_signature(packet_ptr, packet_org);
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
	mem_info base_addr = {NULL, 0};

	find_base_from_list(srv_dll, &base_addr);
	if(!info_players_ptr){
		info_players_ptr = find_signature(info_players, &base_addr);
		get_original_signature(info_players_ptr, info_players_new, info_players_org);
	}

	find_base_from_list(mat_dll, &base_addr);
	if(!lobby_match_ptr){
		lobby_match_ptr = find_signature(lobby_match, &base_addr);
		get_original_signature(lobby_match_ptr, lobby_match_new, lobby_match_org);
	}

	if(!sv_ptr){
	#ifdef WIN32
		uint off = *(uint *)(get_offset(0, &IVEngineServer::GetPlayerInfo)+4);
	#else
		uint off = get_offset(0, &IVEngineServer::GetPlayerInfo)-1;
	#endif
		sv_ptr = *(void **)(*(uint *)(*(uint *)engine+off)+sv_off);
	}
	find_base_from_list(eng_dll, &base_addr);
	if(sv_ptr && !cookie_ptr) cookie_ptr = (void *)((uint)find_signature(cookie, &base_addr)+cookie_off);
	if(!maxslots_ptr){
		maxslots_ptr = find_signature(maxslots, &base_addr);
		get_original_signature(maxslots_ptr, maxslots_new, maxslots_org);
	}
	if(!slots_check_ptr){
	#ifdef WIN32
		slots_check_ptr = maxslots_ptr;
	#else
		slots_check_ptr = find_signature(slots_check, &base_addr);
	#endif
		get_original_signature(slots_check_ptr, slots_check_new, slots_check_org);
	}
	if(!players_running_ptr){
		if((players_running_ptr = find_signature(players_running, &base_addr))){
			if((players_range_ptr = find_signature(players_range, &base_addr))){
				get_original_signature(players_running_ptr, players_running_new, players_running_org);
				write_signature(players_running_ptr, players_running_new);
				get_original_signature(players_range_ptr, players_range_new, players_range_org);
				write_signature(players_range_ptr, players_range_new);
			}
		}
	}
	if(!packet_ptr){
		packet_ptr = (void *)((uint)find_signature(packet, &base_addr, 0)+packet_off);
		get_original_signature(packet_ptr, packet_new, packet_org);
	#ifdef WIN32
		uint ptr = (uint)&HookFunc+3; // push ebp; mov ebp, esp
	#else
		uint ptr = (uint)&HookFunc;
	#endif
		unsigned char call[6] = {0x04, 1};
		*(uint *)(call+2) = (uint)&CheckPacket-ptr-5;
		write_signature((void *)ptr, call);
		write_signature((void *)(ptr+2+2+5), packet_org);
		unsigned char jmp[6] = {0x04, 2+2+5+5+1};
		*(uint *)(jmp+2) = (uint)packet_ptr-ptr-2-2-5-5;
		write_signature((void *)ptr, jmp);
		*(uint *)(packet_new+3) = ptr-(uint)packet_ptr-5;
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
	safe_free(packet_ptr, packet_org);
	return true;
}
