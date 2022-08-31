# 1. 说明
New: 移除对Metamod平台的依赖,改为Source插件  
相对于其他版本l4dtoolz,移除`sv_force_unreserved`(关匹配请`-nomaster`)  
**使用方法: [下载](https://github.com/lakwsh/l4dtoolz/releases/latest)并解压到addons文件夹**  
**如使用tickrate解锁功能,请删除tickrate_enabler**

# 2. 人数破解
## 2.1 最大客户端数(玩家+Bot+特感)(18 ~ 32)
`sv_setmax <num>`  
**注意: 大于18可能导致部分地图报错(地图问题)**
## 2.2 最大玩家数(-1~31)(-1为不做修改)
`sv_maxplayers <num>`(服务器最多能进多少个玩家)
## 2.3 动态移除大厅
`sv_unreserved`(建议配合插件: 大厅满人自动移除)  
此操作会将`sv_allow_lobby_connect_only`的值置0  
**注意: 不移除大厅会限制最大玩家数为4人(coop)**

# 3. 解锁tickrate
**注意: 如通过plugin_load指令手动加载本插件,可能出现tickrate异常问题**
## 3.1 具体用法
在启动项中添加`-tickrate <需要的值>`,不设置则不做任何修改
## 3.2 相关CVar
废弃(存在但改了不会有效果): `sv_maxrate`及`sv_minrate`  
可选(已根据启动项自动设置): `sv_minupdaterate`及`sv_maxupdaterate`  
建议修改:  
`sv_mincmdrate`,`sv_maxcmdrate`,`nb_update_frequency`  
`sv_client_min_interp_ratio`,`sv_client_max_interp_ratio`  
`net_splitrate`,`net_splitpacket_maxrate`  
必须修改(建议写到server.cfg): `fps_max`(每关都要改,引擎限制)

# 4. 绕过SteamID验证
功能开关: `sv_steam_bypass`(置1为不验证SteamID)  
本功能理论上可以避免`No Steam logon`踢出(仅限开启状态下进入游戏的玩家)  
**注意: 目前Win系统会出现A2S_INFO查询不到人数的Bug(原因未知)**

# 5. 主要特色
## 5.1 更安全
比原版依赖更少签名(寻址方式不同,失效几率低)  
**对于没有启用过的功能,默认不作寻址操作**
## 5.2 可动态修改最大玩家数
原版l4dtoolz最大客户端数为固定值32(建议在服务器闲置状态下修改)
## 5.3 关于tickrate解锁
效果与tickrate_enabler基本相同,但是寻址方式完全重写

# 6. 相关插件
## 配套纯净多人插件(可选)
**注意: 该SourceMod插件专为此版本扩展编写,需要安装SourceMod平台**  
[功能：自动移除大厅、允许投票设置最大玩家数](https://github.com/lakwsh/l4d2_rmc)
