# 1. 安装
**解压到addons文件夹即可,请确保安装了metamod**

# 2. 指令
## 2.1 最大支持人数(客户端数)(18 ~ 64)
`maxplayers <num>`  
**注意: 大于32会导致绝大部分sourcemod插件报错,大于18会导致部分地图报错(地图问题)**
## 2.2 最大玩家人数(-1~32)
`sv_maxplayers <num>`
## 2.3 禁止创建大厅
`sv_force_unreserved 1`  
**注意: 不禁止大厅会限制最大玩家数为4人,在游戏里执行指令需要用map换图才能生效**
## 2.4 允许部分作弊指令
`sv_allow_cheats 1`  
**注意: 无需将sv_cheats的值设为1,因多人原因其他不支持的指令就算解除限制也没有实际效果**  
提示以下信息表示该指令不支持  
`Can't use cheat command sb_takecontrol in multiplayer, unless the server has sv_cheats set to 1.`
