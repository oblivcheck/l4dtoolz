# 1. 说明
New: 支持tickrate解锁(即无需安装tickrate_enabler)  
移除`sv_force_unreserved`(用处不大且会导致回话不可用问题)  
**解压到addons文件夹即可,请确保安装了metamod平台**  
**注意: metamod版本太旧会导致扩展加载失败**

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

# 4. 主要特色
## 4.1 更安全
比原版依赖更少签名(寻址方式不同,失效几率低)
## 4.2 可动态修改最大玩家数
原版l4dtoolz最大客户端数为固定值32
## 4.3 关于tickrate解锁
效果与tickrate_enabler基本相同,但是寻址方式完全重写  
理论上可动态修改tick值,但是考虑到稳定性没有实现(而且也没啥必要)
