#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <sstream>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <mutex>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

#define PORT 53
#define BUFFER_SIZE 512
#define DEFAULT_REMOTE_DNS "223.5.5.5"
#define DEFAULT_DNS_FILE "dns.txt"

std::string remoteDNS = DEFAULT_REMOTE_DNS;

// DNS报文头部结构体
struct DNSHeader {
    unsigned id : 16;    // 查询标识号
    unsigned rd : 1;     // 期望递归
    unsigned tc : 1;     // 消息截断
    unsigned aa : 1;     // 授权回答
    unsigned opcode : 4; // 操作码
    unsigned qr : 1;     // 查询/响应标志
    unsigned rcode : 4;  // 响应码
    unsigned cd : 1;     // 检查禁用
    unsigned ad : 1;     // 认证数据
    unsigned z : 1;      // 保留，必须为0
    unsigned ra : 1;     // 递归可用
    uint16_t qdcount;    // 问题计数
    uint16_t ancount;    // 回答计数
    uint16_t nscount;    // 权威名称服务器计数
    uint16_t arcount;    // 附加记录计数
};

// DNS 查询结构体
struct Question {
    char* QNAME;
    unsigned short QTYPE;
    unsigned short QCLASS;
};

// 资源记录结构体
struct RR {
    char* NAME;
    unsigned short TYPE;
    unsigned short CLASS;
    unsigned int TTL;
    unsigned short RDLENGTH;
    char* RDATA;
};

// 缓存项结构体
struct CacheEntry {
    std::vector<char> response;
    std::chrono::steady_clock::time_point expiry;
};

std::unordered_map<std::string, std::string> dnsTable;
std::unordered_map<std::string, CacheEntry> cache; // DNS缓存
std::mutex cacheMutex; // 缓存的互斥锁
int debugMode = 0;

// 读取并加载dns.txt文件到哈希表
void loadDNSTable(const std::string& filename) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        std::cerr << "无法打开文件: " << filename << std::endl;
        return;
    }

    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string ip, domain;
        if (!(iss >> ip >> domain)) {
            continue; // 跳过格式错误的行
        }
        dnsTable[domain] = ip;
    }

    infile.close();
    if (debugMode != 0)
        std::cout << "DNS表加载完成。" << std::endl;
}

// 将域名转换为DNS查询格式
void formatDNSName(std::string& name) {
    std::string formattedName;
    size_t start = 0, end;
    while ((end = name.find('.', start)) != std::string::npos) {
        formattedName += (char)(end - start);
        formattedName += name.substr(start, end - start);
        start = end + 1;
    }
    formattedName += (char)(name.length() - start);
    formattedName += name.substr(start);
    formattedName += '\0';
    name = formattedName;
}

// 进行递归查询
std::vector<char> queryRemoteDNS(const std::vector<char>& query, const std::string& remoteDNS) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "远程DNS套接字创建失败: " << WSAGetLastError() << std::endl;
        return {};
    }

    sockaddr_in remoteAddr;
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_port = htons(53);
    inet_pton(AF_INET, remoteDNS.c_str(), &remoteAddr.sin_addr);

    sendto(sock, query.data(), query.size(), 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));

    std::vector<char> response(BUFFER_SIZE);
    int addrLen = sizeof(remoteAddr);
    int recvLen = recvfrom(sock, response.data(), response.size(), 0, (struct sockaddr*)&remoteAddr, &addrLen);

    closesocket(sock);

    if (recvLen == SOCKET_ERROR) {
        std::cerr << "远程DNS响应接收失败: " << WSAGetLastError();
        return {};
    }

    response.resize(recvLen);
    if (debugMode != 0) {
        std::cout << "从远程DNS收到响应，长度: " << recvLen << std::endl;
    }
    return response;
}

// 处理DNS查询请求
void handleQuery(SOCKET socket, sockaddr_in clientAddr, char* buffer, int bufferLen, const std::string& remoteDNS) {
    DNSHeader* dnsHeader = (DNSHeader*)buffer;

    if (dnsHeader->qr == 0) {
        // 解析查询的域名
        char* qname = buffer + sizeof(DNSHeader);
        std::string domain;
        while (*qname) {
            int len = *qname++;
            while (len-- > 0) {
                domain += *qname++;
            }
            if (*qname) domain += '.';
        }

        if (debugMode != 0) {
            std::cout << "收到查询请求，域名: " << domain << std::endl;
        }

        // 检查缓存
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = cache.find(domain);
            if (it != cache.end() && it->second.expiry > std::chrono::steady_clock::now()) {
                // 在缓存中找到有效条目
                sendto(socket, it->second.response.data(), it->second.response.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
                if (debugMode != 0) {
                    std::cout << "在缓存中找到记录，发送响应。" << std::endl;
                }
                return;
            }
        }

        // 在本地哈希表中查找记录
        std::string responseIP;
        auto it = dnsTable.find(domain);
        if (it != dnsTable.end()) {
            // 在本地哈希表中找到记录
            responseIP = it->second;
            if (debugMode != 0) {
                std::cout << "在本地DNS表中找到IP地址: " << responseIP << std::endl;
            }

            // 构建响应报文
            std::vector<unsigned char> response(BUFFER_SIZE);
            DNSHeader* responseHeader = (DNSHeader*)response.data();
            memcpy(responseHeader, dnsHeader, sizeof(DNSHeader));
            responseHeader->qr = 1; // 标记为响应
            responseHeader->ancount = htons(1); // 一个回答
            responseHeader->ra = 1; // 支持递归查询
            responseHeader->aa = 1; // 授权回答

            // 查询部分
            unsigned char* responseQname = response.data() + sizeof(DNSHeader);
            memcpy(responseQname, buffer + sizeof(DNSHeader), strlen((char*)buffer + sizeof(DNSHeader)) + 1);

            // 查询类型和类字段
            unsigned char* queryTypeClass = responseQname + strlen((char*)responseQname) + 1; // 跳过查询的 QNAME 字段
            queryTypeClass += 2 + 2; // 跳过 QTYPE 和 QCLASS 字段

            // 移动指针到回答部分开始位置
            unsigned char* responseAns = queryTypeClass;

            // 构建资源记录
            // 使用指针指向查询部分的名称
            *responseAns++ = 0xc0;
            *responseAns++ = sizeof(DNSHeader);

            // 类型字段（A记录）
            uint16_t type = htons(1);
            memcpy(responseAns, &type, sizeof(type));
            responseAns += sizeof(type);

            // 类字段（IN类）
            uint16_t class_ = htons(1);
            memcpy(responseAns, &class_, sizeof(class_));
            responseAns += sizeof(class_);

            // 生存时间字段（TTL）
            uint32_t ttl = htonl(3600); // 3600秒
            memcpy(responseAns, &ttl, sizeof(ttl));
            responseAns += sizeof(ttl);

            // 数据长度字段
            uint16_t rdlength = htons(4);
            memcpy(responseAns, &rdlength, sizeof(rdlength));
            responseAns += sizeof(rdlength);

            // 数据字段（IPv4地址）
            struct in_addr addr;
            inet_pton(AF_INET, responseIP.c_str(), &addr);
            memcpy(responseAns, &addr, sizeof(addr));
            responseAns += sizeof(addr);

            int responseLen = responseAns - response.data();
            sendto(socket, (char*)response.data(), responseLen, 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
            if (debugMode != 0) {
                std::cout << "发送响应给客户端，长度: " << responseLen << std::endl;
            }

            // 更新缓存
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                cache[domain] = { std::vector<char>(response.begin(), response.begin() + responseLen), std::chrono::steady_clock::now() + std::chrono::seconds(3600) };
            }
        }
        else {
            // 本地未找到，进行递归查询
            if (debugMode != 0) {
                std::cout << "本地未找到记录，进行递归查询。" << std::endl;
            }
            std::vector<char> query(buffer, buffer + bufferLen);
            std::vector<char> remoteResponse = queryRemoteDNS(query, remoteDNS);
            if (!remoteResponse.empty()) {
                sendto(socket, remoteResponse.data(), remoteResponse.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
                if (debugMode != 0) {
                    std::cout << "发送远程DNS响应给客户端，长度: " << remoteResponse.size() << std::endl;
                }

                // 更新缓存
                {
                    std::lock_guard<std::mutex> lock(cacheMutex);
                    cache[domain] = { std::move(remoteResponse), std::chrono::steady_clock::now() + std::chrono::seconds(3600) };
                }
            }
        }
    }
}


int main(int argc, char* argv[]) {
    std::string dnsFile = DEFAULT_DNS_FILE;

    // 处理命令行参数
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-d" || arg == "-dd") {
            (arg == "-d") ? debugMode = 1 : debugMode = -1;
            if (argc > 3) {
                remoteDNS = argv[2];
                dnsFile = argv[3];
            }
        }
        else {
            if (argc > 2) {
                remoteDNS = argv[1];
                dnsFile = argv[2];
            }
        }
    }

    // 加载DNS表
    loadDNSTable(dnsFile);

    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr, clientAddr;
    char buffer[BUFFER_SIZE];
    int clientAddrLen = sizeof(clientAddr);

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 创建UDP套接字
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "套接字创建失败: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // 绑定套接字
    if (bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "绑定失败: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    if (debugMode != 0)
        std::cout << "DNS服务器正在监听端口 " << PORT << std::endl;

    // 循环接收DNS查询请求
    while (true) {
        int recvLen = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (recvLen == SOCKET_ERROR) {
            if (debugMode != 0)
                std::cerr << "接收失败: " << WSAGetLastError() << std::endl;
            continue;
        }

        if (debugMode != 0) {
            std::cout << "收到查询请求，长度: " << recvLen << std::endl;
        }

        // 启动一个新线程处理查询请求
        std::thread(handleQuery, sock, clientAddr, buffer, recvLen, remoteDNS).detach();
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
