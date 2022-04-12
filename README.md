# 1. 说明
支持tickrate解锁(无需安装tickrate_enabler)  
移除`sv_force_unreserved`(用处不大且会导致回话不可用)  
**解压到addons文件夹即可,请确保安装了metamod平台**  
**注意: metamod版本太旧会导致扩展加载失败,更新即可**

# 2. 人数破解
## 2.1 最大客户端数(玩家+Bot+特感)(18 ~ 32)
`sv_setmax <num>`  
**注意: 大于18可能导致部分地图报错(地图问题)**
## 2.2 最大玩家数(-1~31)(-1为不做修改)
`sv_maxplayers <num>`
## 2.3 动态移除大厅
`sv_unreserved`  
此操作会将`sv_allow_lobby_connect_only`的值置0  
**注意: 不移除大厅会限制最大玩家数为4人**

# 3. 解锁tickrate
具体用法与tickrate_enabler相同,相关功能已重写  
解锁tickrate需要在启动项中设置,不设置默认不开启相关功能  
如`-tickrate 100`,注意**每关需设置fps_max(引擎限制)**  
动态修改tick值理论上可行,但是考虑到稳定性没有实现

# 4. 阻止steam掉线踢出玩家
阻止服务器自动踢出steam掉线的玩家  
将`sv_logon_kick`的值设置为0即可  
**玩家通常会因为steam掉线被踢而崩溃**

# 5. 主要特色
## 5.1 更安全
比原版依赖更少签名
## 5.2 可动态修改最大玩家数
原版最大客户端数为固定值(为31 or 32)
