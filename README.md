     _       __     __   _____            __        __     _____
    | |     / /__  / /_ / ___/____  _____/ /_____  / /_   /__  /
    | | /| / / _ \/ __ \\__ \/ __ \/ ___/ //_/ _ \/ __/_____/ /
    | |/ |/ /  __/ /_/ /__/ / /_/ / /__/ ,< /  __/ /_/_____/ /__
    |__/|__/\___/_.___/____/\____/\___/_/|_|\___/\__/     /____/


#更新历史#
**2016-03-08**

新增：

 - 掩码后的payload报文解析

**2016-03-03**

新增：

 - opcode解析及显示


**2015-12-24**

功能：解析缺失http建链过程的websocket报文。

 - 可识的websocket payload类型：Text、binary(不支持二进制解析)、Ping、Pong、Close
 - 可识别和解析mask-key
 - 支持的payload长度为7 bits, 7+16 bits(payload len==126)

待开发：

 - 被mask的payload字段的编解码
 - 7+64 bits长度的payload支持(payload len==127)
 - 报文分片



#**使用方法**#

1.将WebSocket-Z.lua拷贝到wireshark的插件目录(wireshark的插件目录随版本不同而有所相同)，比如c:\Program Files\Wireshark\plugins\2.0.1\

2.打开待解析报文，在“decode as”菜单中选择“WebSocket-Z”即可

#**注意事项**#

1.因websocket不具备知名端口号，所以可能会对某些非websocket报文进行误解析，但不影响websocket报文自身解析
