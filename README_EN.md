# L4DToolZ
- Installation: [Download](https://github.com/lakwsh/l4dtoolz/releases/latest) and unzip to the addons folder
- **If you are using the tickrate unlock feature, please delete tickrate_enabler**
- If you encounter any issues, please first input `plugin_print` into the **server console** to confirm that the extension has been correctly loaded

## 1. Player Number Unlock
### 1.1 Maximum Number of Clients (i.e., MaxClients) (18 ~ 32)
#### `sv_setmax <num>`
- It is advised not to set the maximum value over 31, as there may be crash issues following `The Last Stand` update
- **The engine default value is 18. If you require the default 31 clients, add `+sv_setmax 31` to the launch options**
### 1.2 Maximum Number of Players (-1~31)
#### `sv_maxplayers <num>`
- The maximum number of players that the server can accommodate (setting to -1 means no change)
### 1.3 Disable Lobby Matching
#### `sv_force_unreserved <0/1>`(set to 1 to disable)
- Enabling this feature will set `sv_allow_lobby_connect_only` to 0
- Once this feature is enabled, the server **will not process** lobby match requests (and there won't be a lobby cookie)
### 1.4 Get/Set Lobby Cookie
#### `sv_cookie <cookie>`
- Typically, you do not need to use this command manually. It is recommended to use the [Dynamic Lobby Plugin](https://github.com/lakwsh/l4d2_rmc) for automatic management
- Setting `cookie` to 0 will remove the lobby, and `sv_allow_lobby_connect_only` will be automatically set to 0
- When `cookie` is not 0, `sv_allow_lobby_connect_only` will be automatically set to 1
- **Note: Not removing the lobby will limit the maximum number of players to 4 for campaigns/8 for versus**

## 2. Tickrate Unlock
- Add `-tickrate <tick>` to the launch options. If not set, no changes will be made
- **Note: If this extension is manually loaded through the plugin_load command, tickrate abnormality may occur**
### 2.1 Related CVar
- The following need to be modified (write to server.cfg, some cvars require the sm_cvar prefix):
- `sv_minupdaterate`, `sv_maxupdaterate`, `sv_mincmdrate`, `sv_maxcmdrate`,
- `nb_update_frequency`, `sv_client_min_interp_ratio`, `fps_max`,
- `sv_client_max_interp_ratio`, `net_splitrate`, `net_splitpacket_maxrate`

## 3. Bypass SteamID Verification
#### `sv_steam_bypass <0/1>`(set to 1 to not verify SteamID)
- This feature can help to avoid the `No Steam logon` (code 6) error (only applicable to players who join while this feature is enabled)
- Enabling this feature **may weaken server security**, and the prohibition of family sharing will become ineffective
- **Note: Enabling this feature may cause A2S to not be able to query the player count. This can be fixed with a patch (see releases)**

## 4. Disabling Family Sharing (No Dependency)
#### `sv_anti_sharing`(set to 1 to enable the feature)
- Enabling this feature will fully prevent family sharing accounts (alt accounts) from joining the server

## 5. Main Features
### 5.1 More Reliable
- Compared to the original l4dtoolz and tickrate_enabler, this is much less dependent on signatures
- Uses offset addressing, reducing the chance of this extension becoming ineffective due to game updates
- Rewrites most of the features, significantly improving reliability
### 5.2 Dynamically Modifiable MaxClients
- The original maximum client count is a fixed value of 32 (it is recommended to modify when the server is idle, otherwise it may crash)

## 6. Recommended Plugins
#### [Complementary Pure Multiplayer & Dynamic Lobby Plugin (Optional)](https://github.com/lakwsh/l4d2_rmc)
- Features: Automatically removes the lobby, allows voting to set the maximum player count
