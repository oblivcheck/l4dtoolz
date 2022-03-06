# 1. 安装
**解压到addons文件夹即可,请确保安装了metamod平台**  
**注意: metamod版本太旧会导致扩展加载失败,更新即可**

# 2. 指令
## 2.1 最大客户端数(玩家+Bot+特感)(18 ~ 31)
`maxplayers <num>`  
**注意: 大于18可能导致部分地图报错(地图问题)**
## 2.2 最大玩家数(-1~31)(-1为不做修改)
`sv_maxplayers <num>`
## 2.3 动态移除大厅
`sv_unreserved`  
此操作会将`sv_allow_lobby_connect_only`的值置0  
**注意: 不移除大厅会限制最大玩家数为4人**
