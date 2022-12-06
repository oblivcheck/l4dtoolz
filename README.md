# 1. 说明
New: 移除对Metamod平台的依赖,改为Source插件  
**使用方法: [下载](https://github.com/lakwsh/l4dtoolz/releases/latest)并解压到addons文件夹**  
**如使用tickrate解锁功能,请删除tickrate_enabler**

# 2. 人数破解
## 2.1 最大客户端数(玩家+Bot+特感)(18 ~ 32)
`sv_setmax <num>`  
**如需默认31客户端请在启动项加入`+sv_setmax 31`**  
**注意: 大于18可能导致部分地图崩溃(地图问题)**
## 2.2 最大玩家数(-1~31)(-1为不做修改)
`sv_maxplayers <num>`(服务器最多能进多少个玩家)
## 2.3 获取/设置大厅
`sv_cookie`(建议配合动态大厅插件)  
移除大厅: `sv_cookie 0`(`sv_allow_lobby_connect_only`自动置0)  
设置大厅: `sv_cookie <cookie>`(`sv_allow_lobby_connect_only`自动置1)  
**注意: 不移除大厅会限制最大玩家数为4人(coop模式)**
## 2.4 禁止匹配(非原版实现)
功能开关: `sv_force_unreserved`(置1为禁止)  
开启功能会将`sv_allow_lobby_connect_only`的值置0

# 3. 解锁tickrate
**注意: 如通过plugin_load指令手动加载本插件,可能出现tickrate异常问题**
## 3.1 具体用法
在启动项中添加`-tickrate <需要的值>`,不设置则不做任何修改
## 3.2 相关CVar
废弃(存在但改了不会有效果): `sv_maxrate`及`sv_minrate`  
需要修改(写到server.cfg,部分cvar需要sm_cvar前缀):  
`sv_minupdaterate`,`sv_maxupdaterate`,`sv_mincmdrate`,`sv_maxcmdrate`,  
`nb_update_frequency`,`sv_client_min_interp_ratio`,`fps_max`,  
`sv_client_max_interp_ratio`,`net_splitrate`,`net_splitpacket_maxrate`  

# 4. 绕过SteamID验证
功能开关: `sv_steam_bypass`(置1为不验证SteamID)  
本功能理论上可以避免`No Steam logon`踢出(仅限开启状态下进入游戏的玩家)  
**注意: 开启此功能会有A2S查询不到人数的问题,可以通过补丁修复**

# 5. 禁止家庭共享
功能开关: `sv_anti_sharing`(置1为开启功能)  
New: 开启本功能可以禁止家庭共享帐号(小号)进入服务器(不可与功能4同时启用)

# 6. 主要特色
## 6.1 更安全
相比于原版l4dtoolz和tickrate_enabler几乎不依赖签名  
采用偏移方式寻址,游戏更新此插件失效的几率低  
**对于没有启用过的功能,默认不作寻址操作**
## 6.2 可动态修改最大玩家数
原版最大客户端数为固定值32(建议在服务器闲置状态下修改,否则可能崩溃)
## 6.3 关于tickrate解锁
效果与tickrate_enabler基本相同,但重写了寻址方式,删除无用代码

# 7. 相关插件
## 配套纯净多人插件(可选)
**注意: 该SourceMod插件专为此版本扩展编写,需要安装SourceMod平台**  
[功能：自动移除大厅、允许投票设置最大玩家数](https://github.com/lakwsh/l4d2_rmc)
