# L4DToolZ
### [中文版本](https://github.com/lakwsh/l4dtoolz/blob/main/README.md)
- Installation: [Download](https://github.com/lakwsh/l4dtoolz/actions?query=branch%3Amain) and unzip to the addons folder.
- **If using tickrate unlock feature, please delete tickrate_enabler**
- If you encounter any problem, first input `plugin_print` in the **server console** to confirm that the extension is loaded correctly.

## 1. Player Number Unlock
### 1.1 Maximum client number (i.e., MaxClients) (18 ~ 32)
#### `sv_setmax <num>`
- It is recommended not to set the maximum value above 31, as crashes can occur after `The Last Stand` update.
- **The engine's default value is 18, if you need a default of 31 clients, add `+sv_setmax 31` to the startup options.**
### 1.2 Maximum number of players (-1~31)
#### `sv_maxplayers <num>`
- The maximum number of players the server can accommodate (set to -1 for no modification).
- **This cvar is loaded with delay and cannot be added to the startup options.**
### 1.3 Prohibit Lobby Matching
#### `sv_force_unreserved <0/1>` (set to 1 to disable)
- Activating this function will set the value of `sv_allow_lobby_connect_only` to 0.
- After this feature is activated, the server **will not process** lobby matching requests (there will also be no lobby cookies).
### 1.4 Get/Set Lobby Cookie
#### `sv_cookie <cookie>`
- Usually, there is no need to use this command manually. It's recommended to use [Dynamic Lobby Plugin](https://github.com/lakwsh/l4d2_rmc) for automatic management.
- A `cookie` of 0 means removing the lobby, and `sv_allow_lobby_connect_only` is automatically set to 0.
- When `cookie` is not 0, `sv_allow_lobby_connect_only` is automatically set to 1.
- **Note: Not removing the lobby will limit the maximum number of players to 4 in campaigns and 8 in versus mode.**

## 2. Tickrate Unlock
- Add `-tickrate <tick>` to the startup options, if not set, no modification will be made.
- **Note: If this extension is manually loaded through the plugin_load command, tickrate anomalies may occur.**
### 2.1 Related CVars
- Need to modify (write to server.cfg, some cvars need sm_cvar prefix):
- `sv_minupdaterate`,`sv_maxupdaterate`,`sv_mincmdrate`,`sv_maxcmdrate`,
- `nb_update_frequency`,`sv_client_min_interp_ratio`,`fps_max`,
- `sv_client_max_interp_ratio`,`net_splitrate`,`net_splitpacket_maxrate`

## 3. Bypass SteamID Verification
#### `sv_steam_bypass <0/1>`(set to 1 to disable SteamID verification)
- This feature can avoid the appearance of `No Steam logon` (code 6) (only for players entering under enabled status).
- Activating this function **will weaken server security**, and the family sharing feature will be invalidated.
- **This cvar is loaded with delay and cannot be added to the startup options.**
- **Note: Enabling this feature may result in the issue that A2S query can't get the number of players, which can be fixed by patches (see releases).**

## 4. Disable Family Sharing (No dependency)
#### `sv_anti_sharing` (set to 1 to enable this function)
- Activating this function can completely prohibit family shared accounts (alt accounts) from entering the server.

## 5. Key Features
### 5.1 More Reliable
- Compared with the original l4dtoolz and tickrate_enabler, it almost doesn't depend on signatures.
- It uses offset addressing, the probability of this extension being invalid due to game updates is low.
- Most features are rewritten, greatly improving reliability.
### 5.2 Dynamically Modifiable MaxClients
- The original maximum client number is a fixed value of 32 (it is recommended to modify it when the server is idle, otherwise it may crash).

## 6. Recommended Plugins
#### [Pure Multiplayer & Dynamic Lobby Plugin (Optional)](https://github.com/lakwsh/l4d2_rmc)
- Functions: Automatically removes lobby, allows voting to set the maximum number of players.
