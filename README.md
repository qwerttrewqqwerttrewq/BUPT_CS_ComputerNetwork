# BUPT_CS_CoputerNetwork
北邮计算机学院计网课设速通版  
  
实现了基础的dns服务器功能，包括本地dns列表查询、远程递归查询  
  
未做适配，使用winsock库实现，仅可在windows下使用   
  
仅支持ipv4 A型查询  
  
查询优先级依次为cache、本地列表查询、远程递归查询  
  
采用多线程处理多个查询请求  
  
考虑到程序运行期间不会改动本地列表故未做互斥锁  
  
cache缓存实现了互斥锁，存储本地列表及远程查询到的响应，但是未设置上限  
  
默认dns列表文件为./dns.txt，默认远程dns服务器为阿里云223.5.5.5  
  
列表格式应为"ip 域名"
  
编译生成exe文件依次可使用:  
  
dns.exe [-d/-dd] [serverIP] [filename]来输出调试信息、指定远程DNS服务器IP、指定本地DNS列表  
  
示例：  
dns.exe -dd 1.1.1.1 ./dns.txt  

