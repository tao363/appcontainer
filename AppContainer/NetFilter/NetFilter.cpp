// NetFilter.cpp - Network filter DLL for AppContainer
//
// Hooks network functions using Microsoft Detours to enforce IP:port and domain-based
// network filtering rules. Injected into the child process by the launcher.
//
// Supported APIs:
//   - Winsock: connect, WSAConnect, sendto, getaddrinfo, GetAddrInfoW
//   - WinHTTP: WinHttpConnect, WinHttpSendRequest
//   - DNS API: DnsQuery_A, DnsQuery_W, DnsQueryEx
//
// Configuration via environment variables:
//   _NETFILTER_DEFAULT  = "allow" or "block"
//   _NETFILTER_CONNECT  = "allow:tcp:*:443;block:udp:10.0.0.0/8:*;..."
//   _NETFILTER_DNS      = "allow:api.example.com;block:*.evil.org;..."
//   _NETFILTER_LOG      = path to log file (optional)

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <windns.h>
#include <detours.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "dnsapi.lib")

// ========================================================================
// Data Types
// ========================================================================

enum class FilterAction { ALLOW, BLOCK };
enum class FilterProto  { TCP, UDP, ANY };

struct ConnectRule {
	FilterAction action;
	FilterProto  proto;
	bool         anyHost;
	ULONG        ipAddr;
	ULONG        ipMask;
	bool         anyPort;
	USHORT       portLow;
	USHORT       portHigh;
};

struct DnsRule {
	FilterAction action;
	std::string  domain;
	bool         isWildcard;
};

// ========================================================================
// Globals
// ========================================================================

static FilterAction           g_DefaultPolicy = FilterAction::ALLOW;
static std::vector<ConnectRule> g_ConnectRules;
static std::vector<DnsRule>     g_DnsRules;
static bool                   g_FilterActive = false;

static HANDLE            g_LogFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION  g_LogCS;
static bool              g_LogCSInited = false;

// ========================================================================
// Real function pointers - Winsock
// ========================================================================

static int (WSAAPI *Real_connect)(
	SOCKET s, const struct sockaddr *name, int namelen) = connect;

static int (WSAAPI *Real_WSAConnect)(
	SOCKET s, const struct sockaddr *name, int namelen,
	LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
	LPQOS lpSQOS, LPQOS lpGQOS) = WSAConnect;

static int (WSAAPI *Real_sendto)(
	SOCKET s, const char *buf, int len, int flags,
	const struct sockaddr *to, int tolen) = sendto;

static INT (WSAAPI *Real_getaddrinfo)(
	PCSTR pNodeName, PCSTR pServiceName,
	const ADDRINFOA *pHints, PADDRINFOA *ppResult) = getaddrinfo;

static INT (WSAAPI *Real_GetAddrInfoW)(
	PCWSTR pNodeName, PCWSTR pServiceName,
	const ADDRINFOW *pHints, PADDRINFOW *ppResult) = GetAddrInfoW;

// ========================================================================
// Real function pointers - WinHTTP
// ========================================================================

typedef HINTERNET (WINAPI *FnWinHttpConnect)(
	HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
static FnWinHttpConnect Real_WinHttpConnect = WinHttpConnect;

typedef BOOL (WINAPI *FnWinHttpSendRequest)(
	HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength,
	LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
static FnWinHttpSendRequest Real_WinHttpSendRequest = WinHttpSendRequest;

typedef HINTERNET (WINAPI *FnWinHttpOpenRequest)(
	HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion,
	LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
static FnWinHttpOpenRequest Real_WinHttpOpenRequest = WinHttpOpenRequest;

// ========================================================================
// Real function pointers - DNS API
// ========================================================================

typedef DNS_STATUS (WINAPI *FnDnsQuery_A)(
	PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra,
	PDNS_RECORD *ppQueryResults, PVOID *pReserved);
static FnDnsQuery_A Real_DnsQuery_A = DnsQuery_A;

typedef DNS_STATUS (WINAPI *FnDnsQuery_W)(
	PCWSTR pszName, WORD wType, DWORD Options, PVOID pExtra,
	PDNS_RECORD *ppQueryResults, PVOID *pReserved);
static FnDnsQuery_W Real_DnsQuery_W = DnsQuery_W;

// ========================================================================
// Logging
// ========================================================================

static void NfLog(const char *fmt, ...) {
	if (g_LogFile == INVALID_HANDLE_VALUE) return;

	EnterCriticalSection(&g_LogCS);

	SYSTEMTIME st{};
	GetLocalTime(&st);

	char prefix[80];
	_snprintf_s(prefix, sizeof(prefix), _TRUNCATE,
		"[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	char body[2048];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(body, sizeof(body), _TRUNCATE, fmt, ap);
	va_end(ap);

	char line[2200];
	_snprintf_s(line, sizeof(line), _TRUNCATE, "%s%s\r\n", prefix, body);

	DWORD written = 0;
	WriteFile(g_LogFile, line, (DWORD)strlen(line), &written, nullptr);

	LeaveCriticalSection(&g_LogCS);
}

// ========================================================================
// Parsing Utilities
// ========================================================================

static std::string TrimA(const std::string &s) {
	size_t b = 0, e = s.size();
	while (b < e && isspace((unsigned char)s[b])) ++b;
	while (e > b && isspace((unsigned char)s[e - 1])) --e;
	return s.substr(b, e - b);
}

static std::string ToLowerA(std::string s) {
	for (auto &ch : s) ch = (char)tolower((unsigned char)ch);
	return s;
}

static std::vector<std::string> SplitA(const std::string &s, char delim) {
	std::vector<std::string> parts;
	size_t pos = 0;
	while (pos < s.size()) {
		size_t next = s.find(delim, pos);
		if (next == std::string::npos) {
			parts.push_back(s.substr(pos));
			break;
		}
		parts.push_back(s.substr(pos, next - pos));
		pos = next + 1;
	}
	return parts;
}

static std::string GetEnvA(const char *name) {
	DWORD need = GetEnvironmentVariableA(name, nullptr, 0);
	if (need == 0) return {};
	std::string buf(need, '\0');
	DWORD got = GetEnvironmentVariableA(name, &buf[0], need);
	if (got == 0 || got >= need) return {};
	buf.resize(got);
	return buf;
}

static std::string WideToNarrow(const wchar_t *ws) {
	if (!ws || !ws[0]) return {};
	int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
	if (len <= 0) return {};
	std::string out(len, '\0');
	WideCharToMultiByte(CP_UTF8, 0, ws, -1, &out[0], len, nullptr, nullptr);
	out.resize(len - 1);
	return out;
}

static std::wstring NarrowToWide(const char *s) {
	if (!s || !s[0]) return {};
	int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
	if (len <= 0) return {};
	std::wstring out(len, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s, -1, &out[0], len);
	out.resize(len - 1);
	return out;
}

// ========================================================================
// IPv4 / Port Parsing
// ========================================================================

static bool ParseIPv4Cidr(const char *s, ULONG *outAddr, ULONG *outMask) {
	char ipBuf[64] = {};
	int prefix = 32;

	const char *slash = strchr(s, '/');
	if (slash) {
		size_t len = (size_t)(slash - s);
		if (len >= sizeof(ipBuf)) return false;
		memcpy(ipBuf, s, len);
		ipBuf[len] = '\0';
		prefix = atoi(slash + 1);
		if (prefix < 0 || prefix > 32) return false;
	}
	else {
		strncpy_s(ipBuf, sizeof(ipBuf), s, _TRUNCATE);
	}

	struct in_addr addr;
	if (inet_pton(AF_INET, ipBuf, &addr) != 1) return false;

	*outAddr = ntohl(addr.s_addr);
	*outMask = (prefix == 0) ? 0 : (0xFFFFFFFFUL << (32 - prefix));
	return true;
}

static bool ParsePort(const char *s, USHORT *outLow, USHORT *outHigh) {
	const char *dash = strchr(s, '-');
	if (dash) {
		int lo = atoi(s);
		int hi = atoi(dash + 1);
		if (lo < 0 || lo > 65535 || hi < 0 || hi > 65535 || lo > hi) return false;
		*outLow = (USHORT)lo;
		*outHigh = (USHORT)hi;
		return true;
	}
	int port = atoi(s);
	if (port < 0 || port > 65535) return false;
	*outLow = *outHigh = (USHORT)port;
	return true;
}

// ========================================================================
// Rule Parsing
// ========================================================================

static bool ParseConnectRule(const std::string &token, ConnectRule &rule) {
	auto parts = SplitA(token, ':');
	if (parts.size() != 4) return false;

	std::string action = ToLowerA(TrimA(parts[0]));
	std::string proto  = ToLowerA(TrimA(parts[1]));
	std::string host   = TrimA(parts[2]);
	std::string port   = TrimA(parts[3]);

	if (action == "allow")      rule.action = FilterAction::ALLOW;
	else if (action == "block") rule.action = FilterAction::BLOCK;
	else return false;

	if (proto == "tcp")      rule.proto = FilterProto::TCP;
	else if (proto == "udp") rule.proto = FilterProto::UDP;
	else if (proto == "*")   rule.proto = FilterProto::ANY;
	else return false;

	if (host == "*") {
		rule.anyHost = true;
		rule.ipAddr = 0;
		rule.ipMask = 0;
	}
	else {
		rule.anyHost = false;
		if (!ParseIPv4Cidr(host.c_str(), &rule.ipAddr, &rule.ipMask)) return false;
	}

	if (port == "*") {
		rule.anyPort = true;
		rule.portLow = 0;
		rule.portHigh = 65535;
	}
	else {
		rule.anyPort = false;
		if (!ParsePort(port.c_str(), &rule.portLow, &rule.portHigh)) return false;
	}

	return true;
}

static bool ParseDnsRule(const std::string &token, DnsRule &rule) {
	auto parts = SplitA(token, ':');
	if (parts.size() != 2) return false;

	std::string action = ToLowerA(TrimA(parts[0]));
	std::string domain = ToLowerA(TrimA(parts[1]));

	if (action == "allow")      rule.action = FilterAction::ALLOW;
	else if (action == "block") rule.action = FilterAction::BLOCK;
	else return false;

	if (domain.size() >= 2 && domain[0] == '*' && domain[1] == '.') {
		rule.isWildcard = true;
		rule.domain = domain.substr(2);
	}
	else if (domain == "*") {
		rule.isWildcard = false;
		rule.domain = "*";
	}
	else {
		rule.isWildcard = false;
		rule.domain = domain;
	}

	return true;
}

static void ParseAllRules() {
	std::string defPol = ToLowerA(TrimA(GetEnvA("_NETFILTER_DEFAULT")));
	if (defPol == "block") {
		g_DefaultPolicy = FilterAction::BLOCK;
	}
	else {
		g_DefaultPolicy = FilterAction::ALLOW;
	}

	std::string connectStr = GetEnvA("_NETFILTER_CONNECT");
	if (!connectStr.empty()) {
		auto tokens = SplitA(connectStr, ';');
		for (const auto &tok : tokens) {
			std::string t = TrimA(tok);
			if (t.empty()) continue;
			ConnectRule rule{};
			if (ParseConnectRule(t, rule)) {
				g_ConnectRules.push_back(rule);
			}
			else {
				NfLog("WARN: invalid connect rule: %s", t.c_str());
			}
		}
	}

	std::string dnsStr = GetEnvA("_NETFILTER_DNS");
	if (!dnsStr.empty()) {
		auto tokens = SplitA(dnsStr, ';');
		for (const auto &tok : tokens) {
			std::string t = TrimA(tok);
			if (t.empty()) continue;
			DnsRule rule{};
			if (ParseDnsRule(t, rule)) {
				g_DnsRules.push_back(rule);
			}
			else {
				NfLog("WARN: invalid DNS rule: %s", t.c_str());
			}
		}
	}

	g_FilterActive = !g_ConnectRules.empty() || !g_DnsRules.empty()
	                 || g_DefaultPolicy == FilterAction::BLOCK;

	NfLog("NetFilter loaded: default=%s, connectRules=%zu, dnsRules=%zu",
		g_DefaultPolicy == FilterAction::BLOCK ? "block" : "allow",
		g_ConnectRules.size(), g_DnsRules.size());
}

// ========================================================================
// Rule Matching
// ========================================================================

static FilterAction MatchConnect(FilterProto proto, ULONG ipv4Host, USHORT portHost) {
	for (const auto &r : g_ConnectRules) {
		if (r.proto != FilterProto::ANY && r.proto != proto) continue;
		if (!r.anyHost) {
			if ((ipv4Host & r.ipMask) != (r.ipAddr & r.ipMask)) continue;
		}
		if (!r.anyPort) {
			if (portHost < r.portLow || portHost > r.portHigh) continue;
		}
		return r.action;
	}
	return g_DefaultPolicy;
}

static bool DomainMatchesPattern(const char *hostname, const DnsRule &rule) {
	if (rule.domain == "*") return true;

	if (rule.isWildcard) {
		size_t hostLen = strlen(hostname);
		size_t domLen  = rule.domain.size();

		if (hostLen == domLen && _stricmp(hostname, rule.domain.c_str()) == 0)
			return true;

		if (hostLen > domLen + 1) {
			const char *suffix = hostname + hostLen - domLen;
			if (suffix[-1] == '.' && _stricmp(suffix, rule.domain.c_str()) == 0)
				return true;
		}
		return false;
	}

	return _stricmp(hostname, rule.domain.c_str()) == 0;
}

static FilterAction MatchDns(const char *hostname) {
	if (!hostname || !hostname[0]) return g_DefaultPolicy;

	for (const auto &r : g_DnsRules) {
		if (DomainMatchesPattern(hostname, r))
			return r.action;
	}
	return g_DefaultPolicy;
}

static FilterAction MatchDnsWide(const wchar_t *hostname) {
	if (!hostname || !hostname[0]) return g_DefaultPolicy;
	std::string narrow = WideToNarrow(hostname);
	return MatchDns(narrow.c_str());
}

// ========================================================================
// Helpers
// ========================================================================

static FilterProto GetSocketProto(SOCKET s) {
	int type = 0;
	int len = sizeof(type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0) {
		if (type == SOCK_STREAM) return FilterProto::TCP;
		if (type == SOCK_DGRAM)  return FilterProto::UDP;
	}
	return FilterProto::ANY;
}

static void FormatIPv4(ULONG hostOrder, char *buf, size_t bufLen) {
	_snprintf_s(buf, bufLen, _TRUNCATE, "%u.%u.%u.%u",
		(hostOrder >> 24) & 0xFF, (hostOrder >> 16) & 0xFF,
		(hostOrder >> 8) & 0xFF, hostOrder & 0xFF);
}

// ========================================================================
// Hook Implementations - Winsock
// ========================================================================

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr *name, int namelen) {
	if (!g_FilterActive || !name) return Real_connect(s, name, namelen);

	if (name->sa_family == AF_INET && namelen >= (int)sizeof(sockaddr_in)) {
		const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(name);
		ULONG  ipHost   = ntohl(sin->sin_addr.s_addr);
		USHORT portHost = ntohs(sin->sin_port);
		FilterProto proto = GetSocketProto(s);

		FilterAction action = MatchConnect(proto, ipHost, portHost);

		if (action == FilterAction::BLOCK) {
			char ipStr[32];
			FormatIPv4(ipHost, ipStr, sizeof(ipStr));
			NfLog("BLOCK connect %s:%u (proto=%s)",
				ipStr, portHost,
				proto == FilterProto::TCP ? "tcp" :
				proto == FilterProto::UDP ? "udp" : "any");
			WSASetLastError(WSAEACCES);
			return SOCKET_ERROR;
		}

		if (g_LogFile != INVALID_HANDLE_VALUE) {
			char ipStr[32];
			FormatIPv4(ipHost, ipStr, sizeof(ipStr));
			NfLog("ALLOW connect %s:%u (proto=%s)",
				ipStr, portHost,
				proto == FilterProto::TCP ? "tcp" :
				proto == FilterProto::UDP ? "udp" : "any");
		}
	}
	else if (name->sa_family == AF_INET6) {
		if (g_DefaultPolicy == FilterAction::BLOCK) {
			NfLog("BLOCK connect [IPv6] (default policy)");
			WSASetLastError(WSAEACCES);
			return SOCKET_ERROR;
		}
	}

	return Real_connect(s, name, namelen);
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
	LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
	LPQOS lpSQOS, LPQOS lpGQOS)
{
	if (!g_FilterActive || !name)
		return Real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);

	if (name->sa_family == AF_INET && namelen >= (int)sizeof(sockaddr_in)) {
		const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(name);
		ULONG  ipHost   = ntohl(sin->sin_addr.s_addr);
		USHORT portHost = ntohs(sin->sin_port);
		FilterProto proto = GetSocketProto(s);

		FilterAction action = MatchConnect(proto, ipHost, portHost);
		if (action == FilterAction::BLOCK) {
			char ipStr[32];
			FormatIPv4(ipHost, ipStr, sizeof(ipStr));
			NfLog("BLOCK WSAConnect %s:%u", ipStr, portHost);
			WSASetLastError(WSAEACCES);
			return SOCKET_ERROR;
		}
	}
	else if (name->sa_family == AF_INET6 && g_DefaultPolicy == FilterAction::BLOCK) {
		NfLog("BLOCK WSAConnect [IPv6] (default policy)");
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}

	return Real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

static int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
	const struct sockaddr *to, int tolen)
{
	if (!g_FilterActive || !to)
		return Real_sendto(s, buf, len, flags, to, tolen);

	if (to->sa_family == AF_INET && tolen >= (int)sizeof(sockaddr_in)) {
		const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(to);
		ULONG  ipHost   = ntohl(sin->sin_addr.s_addr);
		USHORT portHost = ntohs(sin->sin_port);

		FilterAction action = MatchConnect(FilterProto::UDP, ipHost, portHost);
		if (action == FilterAction::BLOCK) {
			char ipStr[32];
			FormatIPv4(ipHost, ipStr, sizeof(ipStr));
			NfLog("BLOCK sendto %s:%u (udp)", ipStr, portHost);
			WSASetLastError(WSAEACCES);
			return SOCKET_ERROR;
		}
	}
	else if (to->sa_family == AF_INET6 && g_DefaultPolicy == FilterAction::BLOCK) {
		NfLog("BLOCK sendto [IPv6] (default policy)");
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}

	return Real_sendto(s, buf, len, flags, to, tolen);
}

static INT WSAAPI Hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName,
	const ADDRINFOA *pHints, PADDRINFOA *ppResult)
{
	if (!g_FilterActive || !pNodeName || !pNodeName[0])
		return Real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);

	FilterAction action = MatchDns(pNodeName);
	if (action == FilterAction::BLOCK) {
		NfLog("BLOCK DNS getaddrinfo %s", pNodeName);
		return WSAHOST_NOT_FOUND;
	}

	NfLog("ALLOW DNS getaddrinfo %s", pNodeName);
	return Real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

static INT WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
	const ADDRINFOW *pHints, PADDRINFOW *ppResult)
{
	if (!g_FilterActive || !pNodeName || !pNodeName[0])
		return Real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);

	std::string narrow = WideToNarrow(pNodeName);
	FilterAction action = MatchDns(narrow.c_str());
	if (action == FilterAction::BLOCK) {
		NfLog("BLOCK DNS GetAddrInfoW %s", narrow.c_str());
		return WSAHOST_NOT_FOUND;
	}

	NfLog("ALLOW DNS GetAddrInfoW %s", narrow.c_str());
	return Real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

// ========================================================================
// Hook Implementations - WinHTTP
// ========================================================================

static HINTERNET WINAPI Hook_WinHttpConnect(
	HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
{
	if (!g_FilterActive || !pswzServerName || !pswzServerName[0])
		return Real_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);

	std::string narrow = WideToNarrow(pswzServerName);
	FilterAction action = MatchDns(narrow.c_str());
	if (action == FilterAction::BLOCK) {
		NfLog("BLOCK WinHttpConnect %s:%u", narrow.c_str(), nServerPort);
		SetLastError(ERROR_INTERNET_NAME_NOT_RESOLVED);
		return nullptr;
	}

	NfLog("ALLOW WinHttpConnect %s:%u", narrow.c_str(), nServerPort);
	return Real_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
}

static HINTERNET WINAPI Hook_WinHttpOpenRequest(
	HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion,
	LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags)
{
	if (!g_FilterActive || !pwszObjectName)
		return Real_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion,
			pwszReferrer, ppwszAcceptTypes, dwFlags);

	std::string objNarrow = WideToNarrow(pwszObjectName);
	NfLog("WinHttpOpenRequest: %s", objNarrow.c_str());

	return Real_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion,
		pwszReferrer, ppwszAcceptTypes, dwFlags);
}

static BOOL WINAPI Hook_WinHttpSendRequest(
	HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength,
	LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext)
{
	if (g_FilterActive && pwszHeaders) {
		std::string headersNarrow = WideToNarrow(pwszHeaders);
		NfLog("WinHttpSendRequest headers: %s", headersNarrow.c_str());
	}

	return Real_WinHttpSendRequest(hRequest, pwszHeaders, dwHeadersLength,
		lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}

// ========================================================================
// Hook Implementations - DNS API
// ========================================================================

static DNS_STATUS WINAPI Hook_DnsQuery_A(
	PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra,
	PDNS_RECORD *ppQueryResults, PVOID *pReserved)
{
	if (!g_FilterActive || !pszName || !pszName[0])
		return Real_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

	FilterAction action = MatchDns(pszName);
	if (action == FilterAction::BLOCK) {
		NfLog("BLOCK DnsQuery_A %s (type=%u)", pszName, wType);
		return DNS_ERROR_RCODE_NAME_ERROR;
	}

	NfLog("ALLOW DnsQuery_A %s (type=%u)", pszName, wType);
	return Real_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
}

static DNS_STATUS WINAPI Hook_DnsQuery_W(
	PCWSTR pszName, WORD wType, DWORD Options, PVOID pExtra,
	PDNS_RECORD *ppQueryResults, PVOID *pReserved)
{
	if (!g_FilterActive || !pszName || !pszName[0])
		return Real_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

	std::string narrow = WideToNarrow(pszName);
	FilterAction action = MatchDns(narrow.c_str());
	if (action == FilterAction::BLOCK) {
		NfLog("BLOCK DnsQuery_W %s (type=%u)", narrow.c_str(), wType);
		return DNS_ERROR_RCODE_NAME_ERROR;
	}

	NfLog("ALLOW DnsQuery_W %s (type=%u)", narrow.c_str(), wType);
	return Real_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
}

// ========================================================================
// Logging Initialisation
// ========================================================================

static void InitLog() {
	InitializeCriticalSection(&g_LogCS);
	g_LogCSInited = true;

	std::string logPath = GetEnvA("_NETFILTER_LOG");
	if (logPath.empty()) return;

	g_LogFile = CreateFileA(logPath.c_str(),
		FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);

	if (g_LogFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER sz{};
		if (GetFileSizeEx(g_LogFile, &sz) && sz.QuadPart == 0) {
			const BYTE bom[] = { 0xEF, 0xBB, 0xBF };
			DWORD w = 0;
			WriteFile(g_LogFile, bom, sizeof(bom), &w, nullptr);
		}
	}
}

static void CloseLog() {
	if (g_LogFile != INVALID_HANDLE_VALUE) {
		CloseHandle(g_LogFile);
		g_LogFile = INVALID_HANDLE_VALUE;
	}
	if (g_LogCSInited) {
		DeleteCriticalSection(&g_LogCS);
		g_LogCSInited = false;
	}
}

// ========================================================================
// DLL Entry Point
// ========================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	(void)hinstDLL;
	(void)lpReserved;

	if (DetourIsHelperProcess()) return TRUE;

	if (dwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);

		InitLog();
		ParseAllRules();

		if (g_FilterActive) {
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());

			// Winsock hooks
			DetourAttach(&(PVOID &)Real_connect,      Hook_connect);
			DetourAttach(&(PVOID &)Real_WSAConnect,   Hook_WSAConnect);
			DetourAttach(&(PVOID &)Real_sendto,       Hook_sendto);
			DetourAttach(&(PVOID &)Real_getaddrinfo,  Hook_getaddrinfo);
			DetourAttach(&(PVOID &)Real_GetAddrInfoW, Hook_GetAddrInfoW);

			// WinHTTP hooks
			DetourAttach(&(PVOID &)Real_WinHttpConnect,     Hook_WinHttpConnect);
			DetourAttach(&(PVOID &)Real_WinHttpOpenRequest, Hook_WinHttpOpenRequest);
			DetourAttach(&(PVOID &)Real_WinHttpSendRequest, Hook_WinHttpSendRequest);

			// DNS API hooks
			DetourAttach(&(PVOID &)Real_DnsQuery_A, Hook_DnsQuery_A);
			DetourAttach(&(PVOID &)Real_DnsQuery_W, Hook_DnsQuery_W);

			LONG err = DetourTransactionCommit();
			NfLog("Hooks installed: %s (err=%ld)",
				err == NO_ERROR ? "OK" : "FAILED", err);
		}
		else {
			NfLog("No filter rules active, hooks not installed.");
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		if (g_FilterActive) {
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());

			DetourDetach(&(PVOID &)Real_connect,      Hook_connect);
			DetourDetach(&(PVOID &)Real_WSAConnect,   Hook_WSAConnect);
			DetourDetach(&(PVOID &)Real_sendto,       Hook_sendto);
			DetourDetach(&(PVOID &)Real_getaddrinfo,  Hook_getaddrinfo);
			DetourDetach(&(PVOID &)Real_GetAddrInfoW, Hook_GetAddrInfoW);

			DetourDetach(&(PVOID &)Real_WinHttpConnect,     Hook_WinHttpConnect);
			DetourDetach(&(PVOID &)Real_WinHttpOpenRequest, Hook_WinHttpOpenRequest);
			DetourDetach(&(PVOID &)Real_WinHttpSendRequest, Hook_WinHttpSendRequest);

			DetourDetach(&(PVOID &)Real_DnsQuery_A, Hook_DnsQuery_A);
			DetourDetach(&(PVOID &)Real_DnsQuery_W, Hook_DnsQuery_W);

			DetourTransactionCommit();
		}
		NfLog("NetFilter unloading.");
		CloseLog();
	}

	return TRUE;
}
