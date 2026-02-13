#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <sdkddkver.h>
#include <Windows.h>
#include <UserEnv.h>
#include <sddl.h>
#include <Aclapi.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdarg>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OneCoreUAP.lib")

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

struct SidAttrWrap : public SID_AND_ATTRIBUTES {
	SidAttrWrap(SID_AND_ATTRIBUTES obj) : SID_AND_ATTRIBUTES(obj) {}

	SidAttrWrap(SidAttrWrap&& other) noexcept {
		Sid = nullptr;
		Attributes = 0;
		std::swap(Sid, other.Sid);
		std::swap(Attributes, other.Attributes);
	}

	SidAttrWrap& operator=(SidAttrWrap&& other) noexcept {
		if (this != &other) {
			if (Sid) {
				LocalFree(Sid);
			}
			Sid = nullptr;
			Attributes = 0;
			std::swap(Sid, other.Sid);
			std::swap(Attributes, other.Attributes);
		}
		return *this;
	}

	SidAttrWrap(const SidAttrWrap&) = delete;
	SidAttrWrap& operator=(const SidAttrWrap&) = delete;

	~SidAttrWrap() {
		if (Sid) {
			LocalFree(Sid);
			Sid = nullptr;
		}
	}
};

struct EnvKV {
	std::wstring name;
	std::wstring value;
};
static void LogV(PCWSTR level, PCWSTR fmt, va_list ap);
struct SavedSecurity {
	std::wstring path;
	PSECURITY_DESCRIPTOR sdDacl = nullptr;
	PACL dacl = nullptr;
	bool hasDacl = false;
	bool daclProtected = false;

	PSECURITY_DESCRIPTOR sdSacl = nullptr;
	PACL sacl = nullptr;
	bool hasSacl = false;
};

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif

typedef HRESULT(WINAPI* FnCreatePseudoConsole)(COORD, HANDLE, HANDLE, DWORD, void**);
typedef void (WINAPI* FnClosePseudoConsole)(void*);
typedef HRESULT(WINAPI* FnResizePseudoConsole)(void*, COORD);

static WCHAR* ExeToLaunch = nullptr;
static std::wstring PackageMoniker;
static std::wstring PackageDisplayName;

static std::vector<SidAttrWrap> CapabilityList;
static std::vector<std::wstring> AllowedPaths;
static std::vector<std::wstring> ReadOnlyAllowedPaths; // system paths: grant read/execute only
static std::vector<EnvKV> EnvOverrides;
static std::vector<std::wstring> PathPrependEntries;
static std::vector<SavedSecurity> g_SavedSecurity;

static std::vector<wchar_t> g_CmdLineBuf;
static std::vector<wchar_t> g_ChildEnv;

static bool WaitForExit = true;
static bool RetainProfile = false;
static bool LaunchAsLpac = false;
static bool NoWin32k = false;
static bool PathLowIntegrity = true;
static bool g_ProfileWasCreated = false;
static bool CleanupAllowedSubdirs = false;
static bool g_WaitAutoEnabled = false;
static bool UseNewConsole = true;
static bool UseConPty = false;
static bool HideParentConsole = true;
static bool g_LogEnabled = false;
static bool g_SuppressConsoleLog = false;

// Bun Virtual Drive (B:\~BUN) state
static volatile LONG g_BunCleanupDone = 0;
static bool g_BunDriveMapped = false;
static std::wstring g_BunStagingDir;
static std::wstring g_BunDriveTarget;

static volatile LONG g_RestoreDone = 0;
static volatile LONG g_PathAclModified = 0;

static FnCreatePseudoConsole g_pfnCreatePC = nullptr;
static FnClosePseudoConsole g_pfnClosePC = nullptr;
static bool g_ConPtyAvailable = false;

// Log file state
static HANDLE g_LogFile = INVALID_HANDLE_VALUE;
static std::wstring g_LogFilePath;

// ========================================================================
// Logging
// ========================================================================

// Open log file next to exe. Called once at startup before any logging.
// Log file name: LaunchAppContainer_YYYYMMDD_HHMMSSmmm.log
static void InitLogFile() {
	if (!g_LogEnabled) return;

	wchar_t exePath[MAX_PATH] = {};
	DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) return;

	// Find directory part
	std::wstring dir(exePath, n);
	size_t pos = dir.find_last_of(L"\\/");
	if (pos != std::wstring::npos) {
		dir = dir.substr(0, pos + 1);
	}
	else {
		dir = L".\\";
	}

	// Build timestamped filename
	SYSTEMTIME st{};
	GetLocalTime(&st);
	wchar_t fname[128] = {};
	_snwprintf_s(fname, _countof(fname), _TRUNCATE,
		L"LaunchAppContainer_%04u%02u%02u_%02u%02u%02u%03u.log",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

	g_LogFilePath = dir + fname;

	g_LogFile = CreateFileW(g_LogFilePath.c_str(),
		FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (g_LogFile == INVALID_HANDLE_VALUE) {
		// Fallback: try writing to current directory
		g_LogFilePath = std::wstring(L".\\") + fname;
		g_LogFile = CreateFileW(g_LogFilePath.c_str(),
			FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	if (g_LogFile != INVALID_HANDLE_VALUE) {
		// Write UTF-8 BOM if file is new (empty)
		LARGE_INTEGER fileSize{};
		if (GetFileSizeEx(g_LogFile, &fileSize) && fileSize.QuadPart == 0) {
			const BYTE bom[] = { 0xEF, 0xBB, 0xBF };
			DWORD written = 0;
			WriteFile(g_LogFile, bom, sizeof(bom), &written, nullptr);
		}
	}
}

static void CloseLogFile() {
	if (g_LogFile != INVALID_HANDLE_VALUE) {
		CloseHandle(g_LogFile);
		g_LogFile = INVALID_HANDLE_VALUE;
	}
}

static void LogV(PCWSTR level, PCWSTR fmt, va_list ap) {
	if (!g_LogEnabled) return;

	SYSTEMTIME st{};
	GetLocalTime(&st);

	// Format prefix
	wchar_t prefix[80] = {};
	_snwprintf_s(prefix, _countof(prefix), _TRUNCATE,
		L"[%04u-%02u-%02u %02u:%02u:%02u.%03u][%ls] ",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level);

	// Format message body
	wchar_t body[4096] = {};
	va_list apCopy;
	va_copy(apCopy, ap);
	_vsnwprintf_s(body, _countof(body), _TRUNCATE, fmt, apCopy);
	va_end(apCopy);

	// Write to console
	if (!g_SuppressConsoleLog) {
		wprintf(L"%ls%ls\r\n", prefix, body);
	}

	// Write to log file (UTF-8)
	if (g_LogFile != INVALID_HANDLE_VALUE) {
		// Build complete line: prefix + body + \r\n
		std::wstring line = std::wstring(prefix) + body + L"\r\n";

		// Convert to UTF-8
		int utf8Len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(),
			nullptr, 0, nullptr, nullptr);
		if (utf8Len > 0) {
			std::vector<char> utf8Buf(utf8Len);
			WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.size(),
				utf8Buf.data(), utf8Len, nullptr, nullptr);
			DWORD written = 0;
			WriteFile(g_LogFile, utf8Buf.data(), (DWORD)utf8Len, &written, nullptr);
		}
	}
}

static void LogInfo(PCWSTR fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	LogV(L"INFO", fmt, ap);
	va_end(ap);
}

static void LogWarn(PCWSTR fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	LogV(L"WARN", fmt, ap);
	va_end(ap);
}

static void LogError(PCWSTR fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	LogV(L"ERROR", fmt, ap);
	va_end(ap);
}

static void LogDebug(PCWSTR fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	LogV(L"DEBUG", fmt, ap);
	va_end(ap);
}

// ========================================================================
// String / Path Utilities
// ========================================================================
static bool IsSpace(wchar_t ch) {
	return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
}

static std::wstring TrimCopy(const std::wstring& s) {
	size_t b = 0;
	size_t e = s.size();

	while (b < e && IsSpace(s[b])) ++b;
	while (e > b && IsSpace(s[e - 1])) --e;

	std::wstring t = s.substr(b, e - b);
	if (t.size() >= 2) {
		if ((t.front() == L'"' && t.back() == L'"') || (t.front() == L'\'' && t.back() == L'\'')) {
			t = t.substr(1, t.size() - 2);
		}
	}
	return t;
}

static bool IEquals(const std::wstring& a, const std::wstring& b) {
	return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

static std::wstring ToLowerCopy(std::wstring s) {
	for (auto& ch : s) {
		ch = static_cast<wchar_t>(towlower(ch));
	}
	return s;
}

static std::wstring NormalizePathForCompare(const std::wstring& in) {
	std::wstring p = TrimCopy(in);
	std::replace(p.begin(), p.end(), L'/', L'\\');

	while (p.size() > 3 && !p.empty() && p.back() == L'\\') {
		p.pop_back();
	}

	if (p.size() == 2 && p[1] == L':') {
		p.push_back(L'\\');
	}

	return p;
}

static bool PathEqualsInsensitive(const std::wstring& a, const std::wstring& b) {
	std::wstring na = NormalizePathForCompare(a);
	std::wstring nb = NormalizePathForCompare(b);
	return _wcsicmp(na.c_str(), nb.c_str()) == 0;
}

static bool VectorHasPathInsensitive(const std::vector<std::wstring>& list, const std::wstring& path) {
	for (const auto& item : list) {
		if (PathEqualsInsensitive(item, path)) {
			return true;
		}
	}
	return false;
}

static bool AddAllowedPathUnique(const std::wstring& path) {
	std::wstring p = TrimCopy(path);
	if (p.empty()) return false;
	if (VectorHasPathInsensitive(AllowedPaths, p)) return false;
	AllowedPaths.emplace_back(p);
	return true;
}

static bool AddReadOnlyPathUnique(const std::wstring& path) {
	std::wstring p = TrimCopy(path);
	if (p.empty()) return false;
	if (VectorHasPathInsensitive(ReadOnlyAllowedPaths, p)) return false;
	if (VectorHasPathInsensitive(AllowedPaths, p)) return false; // already full-access
	ReadOnlyAllowedPaths.emplace_back(p);
	return true;
}

static bool AddPathPrependUnique(const std::wstring& path) {
	std::wstring p = TrimCopy(path);
	if (p.empty()) return false;
	if (VectorHasPathInsensitive(PathPrependEntries, p)) return false;
	PathPrependEntries.emplace_back(p);
	return true;
}

static std::wstring GetEnvVarCopy(PCWSTR name) {
	DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
	if (need == 0) {
		return L"";
	}

	std::vector<wchar_t> buf(need);
	DWORD got = GetEnvironmentVariableW(name, buf.data(), need);
	if (got == 0 || got >= need) {
		return L"";
	}

	return std::wstring(buf.data(), got);
}

static bool DirectoryExists(const std::wstring& path) {
	if (path.empty()) return false;
	DWORD attrs = GetFileAttributesW(path.c_str());
	return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static bool IsDotOrDotDot(const wchar_t* name) {
	return name && (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0);
}

static void ClearReadOnlyAttributeIfSet(const std::wstring& path) {
	DWORD attrs = GetFileAttributesW(path.c_str());
	if (attrs == INVALID_FILE_ATTRIBUTES) return;
	if (attrs & FILE_ATTRIBUTE_READONLY) {
		SetFileAttributesW(path.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
	}
}

static DWORD DeleteTreeNoFollow(const std::wstring& path) {
	DWORD attrs = GetFileAttributesW(path.c_str());
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		DWORD e = GetLastError();
		if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
		return e;
	}

	if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
		ClearReadOnlyAttributeIfSet(path);
		if (DeleteFileW(path.c_str())) return ERROR_SUCCESS;
		DWORD e = GetLastError();
		if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
		return e;
	}

	if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
		ClearReadOnlyAttributeIfSet(path);
		if (RemoveDirectoryW(path.c_str())) return ERROR_SUCCESS;
		DWORD e = GetLastError();
		if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
		return e;
	}

	std::wstring search = path;
	if (!search.empty() && search.back() != L'\\') search.push_back(L'\\');
	search.append(L"*");

	WIN32_FIND_DATAW fd{};
	HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (IsDotOrDotDot(fd.cFileName)) continue;
			std::wstring child = path;
			if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
			child.append(fd.cFileName);

			DWORD dw = DeleteTreeNoFollow(child);
			if (dw != ERROR_SUCCESS) {
				LogWarn(L"DeleteTree failed on %ls (%lu)", child.c_str(), dw);
			}
		} while (FindNextFileW(hFind, &fd));

		DWORD e = GetLastError();
		FindClose(hFind);
		if (e != ERROR_NO_MORE_FILES) {
			return e;
		}
	}
	else {
		DWORD e = GetLastError();
		if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
			return e;
		}
	}

	ClearReadOnlyAttributeIfSet(path);
	if (RemoveDirectoryW(path.c_str())) return ERROR_SUCCESS;

	DWORD e = GetLastError();
	if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
	return e;
}

static void DeleteSubdirectoriesOfRoot(const std::wstring& root) {
	std::wstring r = NormalizePathForCompare(root);
	if (r.empty() || r.size() <= 3) {
		LogWarn(L"[Cleanup] Refuse to clean subdirs of drive root: %ls", root.c_str());
		return;
	}
	if (!DirectoryExists(r)) {
		LogInfo(L"[Cleanup] Root not found, skip: %ls", r.c_str());
		return;
	}

	LogDebug(L"[Cleanup] Enumerating subdirectories of: %ls", r.c_str());

	std::wstring search = r;
	if (!search.empty() && search.back() != L'\\') search.push_back(L'\\');
	search.append(L"*");

	WIN32_FIND_DATAW fd{};
	HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
			LogWarn(L"[Cleanup] FindFirstFile failed on %ls (%lu)", r.c_str(), e);
		}
		return;
	}

	int deletedCount = 0;
	int failedCount = 0;
	do {
		if (IsDotOrDotDot(fd.cFileName)) continue;
		if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;

		std::wstring child = r;
		if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
		child.append(fd.cFileName);

		LogDebug(L"[Cleanup] Deleting subdir: %ls (attrs=0x%08lX)", child.c_str(), fd.dwFileAttributes);
		DWORD dw = DeleteTreeNoFollow(child);
		if (dw == ERROR_SUCCESS) {
			LogInfo(L"[Cleanup] Deleted subdir: %ls", child.c_str());
			++deletedCount;
		}
		else {
			LogWarn(L"[Cleanup] Failed to delete subdir: %ls (%lu)", child.c_str(), dw);
			++failedCount;
		}
	} while (FindNextFileW(hFind, &fd));

	FindClose(hFind);
	LogInfo(L"[Cleanup] Subdirectory cleanup for %ls: %d deleted, %d failed", r.c_str(), deletedCount, failedCount);
}

static void CleanupAllowedPathSubdirs() {
	LogInfo(L"[Cleanup] Starting cleanup of %llu allowed path(s)...", (unsigned long long)AllowedPaths.size());
	for (const auto& p : AllowedPaths) {
		DeleteSubdirectoriesOfRoot(p);
	}
	LogInfo(L"[Cleanup] Allowed path subdirectory cleanup complete.");
}

static std::wstring JoinPath(const std::wstring& base, const std::wstring& leaf) {
	if (base.empty()) return leaf;
	if (leaf.empty()) return base;

	std::wstring out = base;
	if (out.back() != L'\\' && out.back() != L'/') {
		out.push_back(L'\\');
	}

	if (leaf.front() == L'\\' || leaf.front() == L'/') {
		out.append(leaf.substr(1));
	}
	else {
		out.append(leaf);
	}

	return out;
}

static std::wstring GetFileNamePart(const std::wstring& path) {
	if (path.empty()) return L"";
	size_t pos = path.find_last_of(L"\\/");
	if (pos == std::wstring::npos) {
		return path;
	}
	return path.substr(pos + 1);
}

static std::wstring GetParentDir(const std::wstring& path) {
	if (path.empty()) return L"";

	std::wstring p = path;
	std::replace(p.begin(), p.end(), L'/', L'\\');

	while (p.size() > 3 && !p.empty() && p.back() == L'\\') {
		p.pop_back();
	}

	size_t pos = p.find_last_of(L'\\');
	if (pos == std::wstring::npos) return L"";
	if (pos == 2 && p[1] == L':') return p.substr(0, 3);
	if (pos == 0) return p.substr(0, 1);
	return p.substr(0, pos);
}

static std::wstring ParseImagePathFromCommandLine(PCWSTR cmdLine) {
	if (!cmdLine) return L"";

	const wchar_t* p = cmdLine;
	while (*p && IsSpace(*p)) ++p;
	if (*p == L'\0') return L"";

	if (*p == L'"') {
		++p;
		const wchar_t* begin = p;
		while (*p && *p != L'"') ++p;
		return std::wstring(begin, p - begin);
	}

	const wchar_t* begin = p;
	while (*p && !IsSpace(*p)) ++p;
	return std::wstring(begin, p - begin);
}

static bool LooksLikeBunImage(const std::wstring& imagePath) {
	std::wstring name = ToLowerCopy(GetFileNamePart(imagePath));
	return name == L"bun" || name == L"bun.exe";
}

static bool CommandLineMentionsBun(PCWSTR cmdLine) {
	if (!cmdLine) return false;
	std::wstring lower = ToLowerCopy(std::wstring(cmdLine));

	if (lower.find(L"bun.exe") != std::wstring::npos) return true;
	if (lower == L"bun") return true;
	if (lower.rfind(L"bun ", 0) == 0) return true;
	if (lower.find(L" bun ") != std::wstring::npos) return true;
	if (lower.find(L"\\bun ") != std::wstring::npos) return true;
	if (lower.find(L"/bun ") != std::wstring::npos) return true;

	return false;
}

static bool LooksLikeOpenCodeImage(const std::wstring& imagePath) {
	std::wstring name = ToLowerCopy(GetFileNamePart(imagePath));
	return name == L"opencode" || name == L"opencode.exe";
}

static std::wstring GetFirstArgTokenLower(PCWSTR cmdLine) {
	if (!cmdLine) return L"";

	const wchar_t* p = cmdLine;
	while (*p && IsSpace(*p)) ++p;
	if (*p == L'\0') return L"";

	if (*p == L'"') {
		++p;
		while (*p && *p != L'"') ++p;
		if (*p == L'"') ++p;
	}
	else {
		while (*p && !IsSpace(*p)) ++p;
	}

	while (*p && IsSpace(*p)) ++p;
	if (*p == L'\0') return L"";

	std::wstring token;
	if (*p == L'"') {
		++p;
		const wchar_t* begin = p;
		while (*p && *p != L'"') ++p;
		token.assign(begin, p - begin);
	}
	else {
		const wchar_t* begin = p;
		while (*p && !IsSpace(*p)) ++p;
		token.assign(begin, p - begin);
	}

	return ToLowerCopy(token);
}

static bool IsOpenCodeTuiInvocation(PCWSTR cmdLine) {
	if (!cmdLine) return false;
	std::wstring image = ParseImagePathFromCommandLine(cmdLine);
	if (!LooksLikeOpenCodeImage(image)) return false;

	std::wstring sub = GetFirstArgTokenLower(cmdLine);
	if (sub.empty()) return true;

	if (sub == L"--help" || sub == L"-h" ||
		sub == L"--version" || sub == L"-v" ||
		sub == L"config" || sub == L"auth" ||
		sub == L"model" || sub == L"provider" ||
		sub == L"mcp" || sub == L"rules" ||
		sub == L"completion" || sub == L"doctor") {
		return false;
	}

	return true;
}

static bool IsConsoleInteractiveSession() {
	DWORD mode = 0;
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) return false;
	if (!GetConsoleMode(hIn, &mode)) return false;
	if (!GetConsoleMode(hOut, &mode)) return false;
	return true;
}

static void AutoEnableWaitForTuiIfNeeded() {
	if (WaitForExit) return;
	if (!ExeToLaunch) return;
	if (!IsConsoleInteractiveSession()) return;

	if (IsOpenCodeTuiInvocation(ExeToLaunch)) {
		WaitForExit = true;
		g_WaitAutoEnabled = true;
		LogWarn(L"wait=false but OpenCode TUI detected; auto-enabled wait=true.");
	}
}

static bool ResolveSubstPath(const std::wstring& inputPath, std::wstring* resolvedPath) {
	if (!resolvedPath) return false;

	std::wstring p = NormalizePathForCompare(inputPath);
	if (p.size() < 2 || p[1] != L':' || !iswalpha(p[0])) {
		return false;
	}

	wchar_t drive[3] = { static_cast<wchar_t>(towupper(p[0])), L':', L'\0' };
	wchar_t target[4096] = {};
	DWORD n = QueryDosDeviceW(drive, target, _countof(target));
	if (n == 0) {
		return false;
	}

	std::wstring firstTarget(target);
	const std::wstring dosPrefix = L"\\??\\";
	if (firstTarget.rfind(dosPrefix, 0) != 0) {
		return false;
	}

	std::wstring mapped = firstTarget.substr(dosPrefix.size());
	if (mapped.size() < 2 || mapped[1] != L':') {
		return false;
	}

	std::wstring tail = p.substr(2);
	*resolvedPath = mapped + tail;
	return true;
}

static void ResolveExePathIfSubst() {
	if (!ExeToLaunch) return;

	std::wstring image = ParseImagePathFromCommandLine(ExeToLaunch);
	if (image.empty()) return;

	LogDebug(L"[SubstResolve] Checking if exe path is on SUBST drive: %ls", image.c_str());

	std::wstring resolved;
	if (ResolveSubstPath(image, &resolved)) {
		if (!PathEqualsInsensitive(image, resolved)) {
			LogInfo(L"[SubstResolve] Executable path is on a SUBST drive. Resolving '%ls' -> '%ls'", image.c_str(), resolved.c_str());

			const wchar_t* p = ExeToLaunch;
			while (*p && IsSpace(*p)) ++p;

			std::wstring argsSuffix;
			bool wasQuoted = false;

			if (*p == L'"') {
				wasQuoted = true;
				++p;
				const wchar_t* end = p;
				while (*end && *end != L'"') ++end;
				if (*end == L'"') {
					argsSuffix = (end + 1);
				}
				else {
					argsSuffix = end;
				}
			}
			else {
				const wchar_t* end = p;
				while (*end && !IsSpace(*end)) ++end;
				argsSuffix = end;
			}

			std::wstring newCmd;
			bool needsQuotes = wasQuoted || (resolved.find(L' ') != std::wstring::npos);
			if (needsQuotes) newCmd = L"\"" + resolved + L"\"";
			else newCmd = resolved;

			newCmd += argsSuffix;

			g_CmdLineBuf.assign(newCmd.begin(), newCmd.end());
			g_CmdLineBuf.push_back(L'\0');
			ExeToLaunch = g_CmdLineBuf.data();
			LogInfo(L"[SubstResolve] New command line: %ls", ExeToLaunch);
		}
		else {
			LogDebug(L"[SubstResolve] Path already resolved, no change needed.");
		}
	}
	else {
		LogDebug(L"[SubstResolve] Not a SUBST drive or resolution not needed.");
	}
}


static void UpsertEnvOverride(const std::wstring& key, const std::wstring& value) {
	if (key.empty() || key.find(L'=') != std::wstring::npos) return;

	for (auto& kv : EnvOverrides) {
		if (IEquals(kv.name, key)) {
			LogDebug(L"[Env] Updating existing override: %ls = %ls (was: %ls)", key.c_str(), value.c_str(), kv.value.c_str());
			kv.value = value;
			return;
		}
	}

	LogDebug(L"[Env] Adding new override: %ls = %ls", key.c_str(), value.c_str());
	EnvOverrides.push_back(EnvKV{ key, value });
}

// ========================================================================
// Default OpenCode Environment Paths
// ========================================================================
static std::wstring GetExeDir(); // forward declaration (defined in INI Config section)

// Only set env var if NOT already present in EnvOverrides (user config takes priority)
static void SetEnvDefaultIfAbsent(const std::wstring& key, const std::wstring& value) {
	for (const auto& kv : EnvOverrides) {
		if (IEquals(kv.name, key)) {
			LogDebug(L"[EnvDefault] Skipping '%ls' (already set to '%ls')", key.c_str(), kv.value.c_str());
			return;
		}
	}
	LogInfo(L"[EnvDefault] Setting default: %ls = %ls", key.c_str(), value.c_str());
	EnvOverrides.push_back(EnvKV{ key, value });
}

static void ApplyDefaultOpenCodeEnvPaths() {
	std::wstring exeDir = GetExeDir();
	if (exeDir.empty()) return;

	// Remove trailing backslash for clean paths
	while (exeDir.size() > 3 && exeDir.back() == L'\\') exeDir.pop_back();

	std::wstring baseDir = JoinPath(exeDir, L"opencode");
	std::wstring workDir = JoinPath(baseDir, L"work");
	std::wstring configDir = JoinPath(baseDir, L"config");
	std::wstring cacheDir = JoinPath(baseDir, L"cache");
	std::wstring dataDir = JoinPath(baseDir, L"data");
	std::wstring tempDir = JoinPath(baseDir, L"temp");

	LogInfo(L"[EnvDefault] Setting up default OpenCode env paths under: %ls", exeDir.c_str());

	// Create directories
	CreateDirectoryW(baseDir.c_str(), nullptr);
	CreateDirectoryW(workDir.c_str(), nullptr);
	CreateDirectoryW(configDir.c_str(), nullptr);
	CreateDirectoryW(cacheDir.c_str(), nullptr);
	CreateDirectoryW(dataDir.c_str(), nullptr);
	CreateDirectoryW(tempDir.c_str(), nullptr);

	// Set environment variables (user config takes priority)
	SetEnvDefaultIfAbsent(L"HOME", workDir);
	SetEnvDefaultIfAbsent(L"USERPROFILE", workDir);
	SetEnvDefaultIfAbsent(L"APPDATA", configDir);
	SetEnvDefaultIfAbsent(L"LOCALAPPDATA", exeDir);
	SetEnvDefaultIfAbsent(L"TEMP", tempDir);
	SetEnvDefaultIfAbsent(L"TMP", tempDir);
	SetEnvDefaultIfAbsent(L"XDG_CONFIG_HOME", configDir);
	SetEnvDefaultIfAbsent(L"XDG_CACHE_HOME", cacheDir);
	SetEnvDefaultIfAbsent(L"XDG_DATA_HOME", dataDir);
	SetEnvDefaultIfAbsent(L"OPENCODE_CONFIG", JoinPath(baseDir, L"opencode.json"));

	// Auto-add all subdirs to AllowedPaths
	std::wstring dirs[] = { baseDir, workDir, configDir, cacheDir, dataDir, tempDir };
	for (const auto& d : dirs) {
		if (AddAllowedPathUnique(d)) {
			LogInfo(L"[EnvDefault] Auto-allowed path: %ls", d.c_str());
		}
	}

	// Auto-add system paths as read-only so child processes can spawn cmd.exe, etc.
	// Note: C:\Windows\System32 already has ALL APPLICATION PACKAGES with Read & Execute
	// in its default ACL, so no explicit grant is needed for AppContainer file access.

	// Also add the opencode data/bin directory for tools like rg.exe
	std::wstring dataBinDir = JoinPath(dataDir, L"opencode\\bin");
	CreateDirectoryW(JoinPath(dataDir, L"opencode").c_str(), nullptr);
	CreateDirectoryW(dataBinDir.c_str(), nullptr);
	if (AddAllowedPathUnique(dataBinDir)) {
		LogInfo(L"[EnvDefault] Auto-allowed path (tools): %ls", dataBinDir.c_str());
	}

	LogInfo(L"[EnvDefault] Default OpenCode env paths applied.");
}

static void ApplyBunOpenTuiCompatibility() {
	if (!ExeToLaunch) return;

	std::wstring imagePath = ParseImagePathFromCommandLine(ExeToLaunch);
	bool bunDetected = LooksLikeBunImage(imagePath) || CommandLineMentionsBun(ExeToLaunch);
	if (!bunDetected) {
		LogDebug(L"[BunCompat] Not a Bun invocation, skipping compatibility setup.");
		return;
	}

	LogInfo(L"[BunCompat] Bun runtime detected in command line.");

	std::wstring bunInstall = TrimCopy(GetEnvVarCopy(L"BUN_INSTALL"));
	if (bunInstall.empty() && !imagePath.empty()) {
		std::wstring imageDir = GetParentDir(imagePath);
		if (IEquals(GetFileNamePart(imageDir), L"bin")) {
			bunInstall = GetParentDir(imageDir);
			LogDebug(L"[BunCompat] Inferred BUN_INSTALL from image path: %ls", bunInstall.c_str());
		}
	}

	if (bunInstall.empty()) {
		LogWarn(L"[BunCompat] bun detected, but BUN_INSTALL is empty. Skip auto path fix.");
		return;
	}

	LogInfo(L"[BunCompat] BUN_INSTALL = %ls", bunInstall.c_str());
	bool changed = false;

	auto applyBase = [&](const std::wstring& base, PCWSTR sourceTag) {
		if (base.empty()) return;

		std::wstring rootPath = JoinPath(base, L"root");
		std::wstring binPath = JoinPath(base, L"bin");

		LogDebug(L"%ls Checking paths: root=%ls, bin=%ls", sourceTag, rootPath.c_str(), binPath.c_str());

		if (DirectoryExists(rootPath)) {
			if (AddAllowedPathUnique(rootPath)) {
				LogInfo(L"%ls Auto allow path: %ls", sourceTag, rootPath.c_str());
				changed = true;
			}
			if (AddPathPrependUnique(rootPath)) {
				LogInfo(L"%ls Auto PATH prepend: %ls", sourceTag, rootPath.c_str());
				changed = true;
			}
		}
		else {
			LogDebug(L"%ls root path does not exist: %ls", sourceTag, rootPath.c_str());
		}

		if (DirectoryExists(binPath)) {
			if (AddPathPrependUnique(binPath)) {
				LogInfo(L"%ls Auto PATH prepend: %ls", sourceTag, binPath.c_str());
				changed = true;
			}
		}
		else {
			LogDebug(L"%ls bin path does not exist: %ls", sourceTag, binPath.c_str());
		}
		};

	applyBase(bunInstall, L"[BunCompat]");

	std::wstring resolvedInstall;
	if (ResolveSubstPath(bunInstall, &resolvedInstall) &&
		!PathEqualsInsensitive(bunInstall, resolvedInstall) &&
		DirectoryExists(resolvedInstall)) {
		UpsertEnvOverride(L"BUN_INSTALL", resolvedInstall);
		LogInfo(L"[BunCompat] Remap BUN_INSTALL for child: %ls -> %ls", bunInstall.c_str(), resolvedInstall.c_str());
		applyBase(resolvedInstall, L"[BunCompat]");
	}

	if (changed) {
		LogInfo(L"[BunCompat] Applied OpenTUI runtime compatibility settings.");
	}
	else {
		LogInfo(L"[BunCompat] No additional Bun path changes were needed.");
	}
}

// ========================================================================
// Capability / SID helpers
// ========================================================================
static void FreeSidArray(PSID* sids, ULONG count) {
	if (!sids) return;
	for (ULONG i = 0; i < count; i++) {
		if (sids[i]) {
			LocalFree(sids[i]);
			sids[i] = nullptr;
		}
	}
	LocalFree(sids);
}

static void PrintUsage() {
	wprintf(L"LaunchAppContainer.exe Usage:\r\n");
	wprintf(L"\t-m Moniker -i ExeToLaunch -c Cap1;Cap2 -a Path1;Path2 -e K1=V1;K2=V2 -p Dir1;Dir2 -s -w -r -l -k -x\r\n");
	wprintf(L"\r\n");
	wprintf(L"Required:\r\n");
	wprintf(L"\t-i : Command line of exe to launch\r\n");
	wprintf(L"\t-m : Package moniker\r\n");
	wprintf(L"\r\n");
	wprintf(L"Optional:\r\n");
	wprintf(L"\t-c : Capabilities (or SIDs)\r\n");
	wprintf(L"\t-d : Display name for profile\r\n");
	wprintf(L"\t-a : Semicolon-separated directories to grant (F)\r\n");
	wprintf(L"\t-e : Semicolon-separated env pairs (K=V;K2=V2)\r\n");
	wprintf(L"\t-p : Semicolon-separated path prepend list\r\n");
	wprintf(L"\t-s : Skip setting Low Integrity on -a paths\r\n");
	wprintf(L"\t-w : Wait for child exit\r\n");
	wprintf(L"\t-r : Retain AppContainer profile after exit\r\n");
	wprintf(L"\t-l : Launch as LPAC\r\n");
	wprintf(L"\t-k : Enable win32k lockdown\r\n");
	wprintf(L"\t-x : Cleanup: recursively delete subdirectories under -a paths after exit (keep roots)\r\n");
	wprintf(L"\t-g : Enable logging (console + file)\r\n");
	wprintf(L"\r\n");
	wprintf(L"Notes:\r\n");
	wprintf(L"\t- Child shares current console window.\r\n");
	wprintf(L"\t- config.ini [App] is auto-loaded when no CLI args.\r\n");
	wprintf(L"\t- For bun/bun.exe, %%BUN_INSTALL%%\\root is auto-added to allowPaths and PATH.\r\n");
}

// ========================================================================
// Argument / Config Parsing
// ========================================================================
static bool ParseCapabilityList(WCHAR* caps) {
	if (!caps) return true;

	WCHAR* ctx = nullptr;
	for (WCHAR* tok = wcstok_s(caps, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
		std::wstring cap = TrimCopy(tok);
		if (cap.empty()) continue;

		SID_AND_ATTRIBUTES sidInfo{};
		sidInfo.Attributes = SE_GROUP_ENABLED;

		if (ConvertStringSidToSidW(cap.c_str(), &sidInfo.Sid)) {
			LogDebug(L"[Caps] Parsed SID string: %ls", cap.c_str());
			CapabilityList.emplace_back(sidInfo);
			continue;
		}

		PSID* capGroupSids = nullptr;
		DWORD capGroupSidsLen = 0;
		PSID* capSids = nullptr;
		DWORD capSidsLen = 0;

		if (DeriveCapabilitySidsFromName(cap.c_str(), &capGroupSids, &capGroupSidsLen, &capSids, &capSidsLen)) {
			LogDebug(L"[Caps] Derived %lu capability SIDs from name: %ls", capSidsLen, cap.c_str());
			for (DWORD i = 0; i < capSidsLen; ++i) {
				CapabilityList.emplace_back(SID_AND_ATTRIBUTES{ capSids[i], SE_GROUP_ENABLED });
			}
			FreeSidArray(capGroupSids, capGroupSidsLen);
			LocalFree(capSids);
			continue;
		}

		LogError(L"Failed to parse capability token: %ls (GetLastError=%lu)", cap.c_str(), GetLastError());
		return false;
	}

	return true;
}

static bool ParseAllowedPathList(WCHAR* paths) {
	if (!paths) return true;

	WCHAR* ctx = nullptr;
	for (WCHAR* tok = wcstok_s(paths, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
		std::wstring p = TrimCopy(tok);
		if (!p.empty()) {
			if (AddAllowedPathUnique(p)) {
				LogInfo(L"Allowed path added: %ls", p.c_str());
			}
			else {
				LogDebug(L"Allowed path ignored (duplicate): %ls", p.c_str());
			}
		}
	}
	return true;
}

static bool ParseEnvList(WCHAR* env) {
	if (!env) return true;

	WCHAR* ctx = nullptr;
	for (WCHAR* tok = wcstok_s(env, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
		std::wstring pair = TrimCopy(tok);
		if (pair.empty()) continue;

		size_t eq = pair.find(L'=');
		std::wstring k = TrimCopy(eq == std::wstring::npos ? pair : pair.substr(0, eq));
		std::wstring v = TrimCopy(eq == std::wstring::npos ? L"" : pair.substr(eq + 1));

		if (!k.empty() && k.find(L'=') == std::wstring::npos) {
			EnvOverrides.push_back(EnvKV{ k, v });
			LogInfo(L"Env override added: %ls = %ls", k.c_str(), v.c_str());
		}
		else {
			LogWarn(L"Ignored invalid env token: %ls", pair.c_str());
		}
	}

	return true;
}

static bool ParsePathPrependList(WCHAR* paths) {
	if (!paths) return true;

	WCHAR* ctx = nullptr;
	for (WCHAR* tok = wcstok_s(paths, L";", &ctx); tok != nullptr; tok = wcstok_s(nullptr, L";", &ctx)) {
		std::wstring p = TrimCopy(tok);
		if (!p.empty()) {
			if (AddPathPrependUnique(p)) {
				LogInfo(L"PATH prepend added: %ls", p.c_str());
			}
			else {
				LogDebug(L"PATH prepend ignored (duplicate): %ls", p.c_str());
			}
		}
	}

	return true;
}

static bool ParseCapabilityListFromArg(PCWSTR arg) {
	if (!arg) return true;
	std::vector<wchar_t> buf(arg, arg + wcslen(arg));
	buf.push_back(L'\0');
	return ParseCapabilityList(buf.data());
}

static bool ParseAllowedPathListFromArg(PCWSTR arg) {
	if (!arg) return true;
	std::vector<wchar_t> buf(arg, arg + wcslen(arg));
	buf.push_back(L'\0');
	return ParseAllowedPathList(buf.data());
}

static bool ParseEnvListFromArg(PCWSTR arg) {
	if (!arg) return true;
	std::vector<wchar_t> buf(arg, arg + wcslen(arg));
	buf.push_back(L'\0');
	return ParseEnvList(buf.data());
}

static bool ParsePathPrependListFromArg(PCWSTR arg) {
	if (!arg) return true;
	std::vector<wchar_t> buf(arg, arg + wcslen(arg));
	buf.push_back(L'\0');
	return ParsePathPrependList(buf.data());
}

static bool ParseArguments(int argc, WCHAR** argv) {
	LogDebug(L"[Args] Parsing %d command-line arguments...", argc);
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] != L'-' && argv[i][0] != L'/') {
			LogDebug(L"[Args] Skipping non-option arg[%d]: %ls", i, argv[i]);
			continue;
		}

		LogDebug(L"[Args] Processing arg[%d]: %ls", i, argv[i]);
		switch (argv[i][1]) {
		case L'i':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			ExeToLaunch = argv[++i];
			LogInfo(L"[Args] exe = %ls", ExeToLaunch);
			break;
		case L'm':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			PackageMoniker = argv[++i];
			LogInfo(L"[Args] moniker = %ls", PackageMoniker.c_str());
			break;
		case L'c':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			if (!ParseCapabilityListFromArg(argv[++i])) return false;
			break;
		case L'd':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			PackageDisplayName = argv[++i];
			LogInfo(L"[Args] displayName = %ls", PackageDisplayName.c_str());
			break;
		case L'a':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			if (!ParseAllowedPathListFromArg(argv[++i])) return false;
			break;
		case L'e':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			if (!ParseEnvListFromArg(argv[++i])) return false;
			break;
		case L'p':
			if (i + 1 >= argc) { PrintUsage(); return false; }
			if (!ParsePathPrependListFromArg(argv[++i])) return false;
			break;
		case L's': PathLowIntegrity = false; LogDebug(L"[Args] lowIntegrity disabled"); break;
		case L'w': WaitForExit = true; LogDebug(L"[Args] wait=true"); break;
		case L'r': RetainProfile = true; LogDebug(L"[Args] retainProfile=true"); break;
		case L'l': LaunchAsLpac = true; LogDebug(L"[Args] lpac=true"); break;
		case L'k': NoWin32k = true; LogDebug(L"[Args] noWin32k=true"); break;
		case L'x': CleanupAllowedSubdirs = true; LogDebug(L"[Args] cleanupSubdirs=true"); break;
		case L'g': g_LogEnabled = true; LogDebug(L"[Args] log=true"); break;
		default:
			LogWarn(L"[Args] Unknown option: %ls", argv[i]);
			break;
		}
	}

	LogInfo(L"[Args] Parse complete: %llu capabilities, %llu allowed paths, %llu env overrides, %llu path prepends",
		(unsigned long long)CapabilityList.size(), (unsigned long long)AllowedPaths.size(),
		(unsigned long long)EnvOverrides.size(), (unsigned long long)PathPrependEntries.size());
	return true;
}

// ========================================================================
// AppContainer Profile Management
// ========================================================================
static DWORD CreateAppContainerProfileWithMoniker(PSID* pAppContainerSid) {
	g_ProfileWasCreated = false;
	*pAppContainerSid = nullptr;

	PCWSTR display = PackageDisplayName.empty() ? PackageMoniker.c_str() : PackageDisplayName.c_str();
	LogInfo(L"[Profile] Creating AppContainer profile: moniker='%ls', display='%ls', caps=%llu",
		PackageMoniker.c_str(), display, (unsigned long long)CapabilityList.size());

	PSID packageSid = nullptr;
	HRESULT hr = CreateAppContainerProfile(
		PackageMoniker.c_str(), display, display,
		CapabilityList.data(),
		static_cast<DWORD>(CapabilityList.size()),
		&packageSid);

	if (SUCCEEDED(hr)) {
		g_ProfileWasCreated = true;
		*pAppContainerSid = packageSid;

		LPWSTR sidStr = nullptr;
		if (ConvertSidToStringSidW(packageSid, &sidStr)) {
			LogInfo(L"[Profile] Created new profile. SID=%ls", sidStr);
			LocalFree(sidStr);
		}
		else {
			LogInfo(L"[Profile] Created new profile successfully.");
		}
		return ERROR_SUCCESS;
	}

	if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
		LogInfo(L"[Profile] Profile already exists, deriving SID...");
		hr = DeriveAppContainerSidFromAppContainerName(PackageMoniker.c_str(), &packageSid);
		if (SUCCEEDED(hr)) {
			*pAppContainerSid = packageSid;
			LPWSTR sidStr = nullptr;
			if (ConvertSidToStringSidW(packageSid, &sidStr)) {
				LogInfo(L"[Profile] Reusing existing profile. SID=%ls", sidStr);
				LocalFree(sidStr);
			}
			return ERROR_SUCCESS;
		}
		DWORD err = HRESULT_CODE(hr);
		LogError(L"[Profile] DeriveAppContainerSidFromAppContainerName failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
		return err;
	}

	DWORD err = HRESULT_CODE(hr);
	LogError(L"[Profile] CreateAppContainerProfile failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
	return err;
}

static DWORD DeleteAppContainerProfileWithMoniker() {
	LogInfo(L"[Profile] Deleting AppContainer profile: %ls", PackageMoniker.c_str());
	HRESULT hr = DeleteAppContainerProfile(PackageMoniker.c_str());
	if (FAILED(hr)) {
		DWORD err = HRESULT_CODE(hr);
		LogWarn(L"[Profile] DeleteAppContainerProfile failed: hr=0x%08lX, err=%lu", (DWORD)hr, err);
		return err;
	}
	LogInfo(L"[Profile] Profile deleted successfully.");
	return ERROR_SUCCESS;
}

// ========================================================================
// Security / ACL Management
// ========================================================================
static DWORD GrantFullControlToSidOnPath(PCWSTR path, PSID sid) {
	LogDebug(L"[ACL] GrantFullControl on: %ls", path);
	PSECURITY_DESCRIPTOR sd = nullptr;
	PACL oldDacl = nullptr;

	DWORD dw = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		nullptr, nullptr, &oldDacl, nullptr, &sd);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] GetNamedSecurityInfoW failed on %ls: err=%lu", path, dw);
		return dw;
	}

	EXPLICIT_ACCESSW ea{};
	ea.grfAccessPermissions = FILE_ALL_ACCESS;
	ea.grfAccessMode = GRANT_ACCESS;
	ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	BuildTrusteeWithSidW(&ea.Trustee, sid);

	PACL newDacl = nullptr;
	dw = SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] SetEntriesInAclW failed on %ls: err=%lu", path, dw);
		if (sd) LocalFree(sd);
		return dw;
	}

	dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] SetNamedSecurityInfoW (DACL) failed on %ls: err=%lu", path, dw);
	}
	else {
		LogDebug(L"[ACL] Successfully granted FILE_ALL_ACCESS on: %ls", path);
	}

	if (newDacl) LocalFree(newDacl);
	if (sd) LocalFree(sd);
	return dw;
}

static DWORD GrantReadExecuteToSidOnPath(PCWSTR path, PSID sid) {
	LogDebug(L"[ACL] GrantReadExecute on: %ls", path);
	PSECURITY_DESCRIPTOR sd = nullptr;
	PACL oldDacl = nullptr;

	DWORD dw = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		nullptr, nullptr, &oldDacl, nullptr, &sd);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] GetNamedSecurityInfoW failed on %ls: err=%lu", path, dw);
		return dw;
	}

	EXPLICIT_ACCESSW ea{};
	ea.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	ea.grfAccessMode = GRANT_ACCESS;
	ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	BuildTrusteeWithSidW(&ea.Trustee, sid);

	PACL newDacl = nullptr;
	dw = SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] SetEntriesInAclW failed on %ls: err=%lu", path, dw);
		if (sd) LocalFree(sd);
		return dw;
	}

	dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
	if (dw != ERROR_SUCCESS) {
		LogError(L"[ACL] SetNamedSecurityInfoW (DACL) failed on %ls: err=%lu", path, dw);
	}
	else {
		LogDebug(L"[ACL] Successfully granted READ_EXECUTE on: %ls", path);
	}

	if (newDacl) LocalFree(newDacl);
	if (sd) LocalFree(sd);
	return dw;
}

static DWORD SetLowIntegrityLabel(PCWSTR path) {
	LogDebug(L"[ACL] Setting Low Integrity label on: %ls", path);
	PSECURITY_DESCRIPTOR sd = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &sd, nullptr)) {
		DWORD err = GetLastError();
		LogError(L"[ACL] ConvertStringSecurityDescriptorToSecurityDescriptorW failed: err=%lu", err);
		return err;
	}

	PACL sacl = nullptr;
	BOOL present = FALSE, defaulted = FALSE;
	if (!GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted)) {
		DWORD err = GetLastError();
		LogError(L"[ACL] GetSecurityDescriptorSacl failed: err=%lu", err);
		LocalFree(sd);
		return err;
	}

	DWORD dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
		LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, sacl);
	if (dw != ERROR_SUCCESS) {
		LogWarn(L"[ACL] SetNamedSecurityInfoW (SACL/LowIntegrity) failed on %ls: err=%lu (needs elevation)", path, dw);
	}
	else {
		LogDebug(L"[ACL] Low Integrity label set successfully on: %ls", path);
	}

	LocalFree(sd);
	return dw;
}

static DWORD RestoreDaclWithProtection(const SavedSecurity& ss) {
	if (!ss.hasDacl) return ERROR_INVALID_PARAMETER;
	DWORD flags = DACL_SECURITY_INFORMATION;
	flags |= ss.daclProtected ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
	return SetNamedSecurityInfoW(const_cast<LPWSTR>(ss.path.c_str()), SE_FILE_OBJECT,
		flags, nullptr, nullptr, ss.dacl, nullptr);
}

static DWORD SaveOriginalSecurityForPath(PCWSTR path) {
	LogDebug(L"[Security] Saving original security descriptor for: %ls", path);
	SavedSecurity ss{};
	ss.path = path;

	DWORD daclErr = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		nullptr, nullptr, &ss.dacl, nullptr, &ss.sdDacl);
	if (daclErr == ERROR_SUCCESS) {
		ss.hasDacl = true;
		SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
		DWORD rev = 0;
		if (GetSecurityDescriptorControl(ss.sdDacl, &ctrl, &rev)) {
			ss.daclProtected = (ctrl & SE_DACL_PROTECTED) != 0;
		}
		LogInfo(L"[Security] Backed up DACL for %ls (protected=%d, revision=%lu)", path, ss.daclProtected ? 1 : 0, rev);
	}
	else {
		LogWarn(L"[Security] Failed to backup DACL for %ls (err=%lu)", path, daclErr);
	}

	DWORD saclErr = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
		nullptr, nullptr, nullptr, &ss.sacl, &ss.sdSacl);
	if (saclErr == ERROR_SUCCESS) {
		ss.hasSacl = true;
		LogInfo(L"[Security] Backed up Label SACL for %ls", path);
	}
	else {
		LogWarn(L"[Security] Failed to backup Label SACL for %ls (err=%lu)", path, saclErr);
	}

	g_SavedSecurity.emplace_back(ss);
	return (daclErr == ERROR_SUCCESS || saclErr == ERROR_SUCCESS) ? ERROR_SUCCESS
		: (daclErr != ERROR_SUCCESS ? daclErr : saclErr);
}

static void RestoreSavedSecurity() {
	LogInfo(L"[Revert] Restoring original security on %llu path(s)...", (unsigned long long)g_SavedSecurity.size());
	int restoredDacl = 0, restoredSacl = 0, failedDacl = 0, failedSacl = 0;

	for (auto& ss : g_SavedSecurity) {
		if (ss.hasDacl) {
			DWORD dw = RestoreDaclWithProtection(ss);
			if (dw == ERROR_SUCCESS) {
				LogInfo(L"[Revert] Restored DACL on %ls (protected=%d)", ss.path.c_str(), ss.daclProtected ? 1 : 0);
				++restoredDacl;
			}
			else {
				LogWarn(L"[Revert] Failed to restore DACL on %ls (err=%lu)", ss.path.c_str(), dw);
				++failedDacl;
			}
		}
		if (ss.hasSacl) {
			DWORD dw = SetNamedSecurityInfoW(const_cast<LPWSTR>(ss.path.c_str()), SE_FILE_OBJECT,
				LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, ss.sacl);
			if (dw == ERROR_SUCCESS) {
				LogInfo(L"[Revert] Restored Label SACL on %ls", ss.path.c_str());
				++restoredSacl;
			}
			else {
				LogWarn(L"[Revert] Failed to restore Label SACL on %ls (err=%lu)", ss.path.c_str(), dw);
				++failedSacl;
			}
		}
		if (ss.sdDacl) { LocalFree(ss.sdDacl); ss.sdDacl = nullptr; }
		if (ss.sdSacl) { LocalFree(ss.sdSacl); ss.sdSacl = nullptr; }
	}
	g_SavedSecurity.clear();

	LogInfo(L"[Revert] Security restore complete: DACL restored=%d failed=%d, SACL restored=%d failed=%d",
		restoredDacl, failedDacl, restoredSacl, failedSacl);
}

static void RestoreSavedSecurityOnce() {
	if (InterlockedCompareExchange(&g_RestoreDone, 1, 0) != 0) {
		LogDebug(L"[Revert] RestoreSavedSecurityOnce already executed, skipping.");
		return;
	}
	if (InterlockedCompareExchange(&g_PathAclModified, 0, 0) == 1) {
		RestoreSavedSecurity();
	}
	else {
		LogDebug(L"[Revert] No path ACLs were modified, nothing to restore.");
	}
}

static void GrantAccessToAllowedPaths(PSID appContainerSid) {
	LogInfo(L"[Permissions] Granting access to %llu allowed path(s)...", (unsigned long long)AllowedPaths.size());
	int grantedCount = 0, skippedCount = 0, failedCount = 0;

	for (const auto& path : AllowedPaths) {
		DWORD attrs = GetFileAttributesW(path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES) {
			wprintf(L"[Skip] Path not found: %ls (err=%lu)\r\n", path.c_str(), GetLastError());
			LogWarn(L"[Permissions] Skip path (not found): %ls (err=%lu)", path.c_str(), GetLastError());
			++skippedCount;
			continue;
		}
		if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
			wprintf(L"[Skip] Not a directory: %ls (attrs=0x%08lX)\r\n", path.c_str(), attrs);
			LogWarn(L"[Permissions] Skip path (not directory): %ls (attrs=0x%08lX)", path.c_str(), attrs);
			++skippedCount;
			continue;
		}

		LogDebug(L"[Permissions] Processing path: %ls (attrs=0x%08lX)", path.c_str(), attrs);

		SaveOriginalSecurityForPath(path.c_str());
		SavedSecurity* backup = g_SavedSecurity.empty() ? nullptr : &g_SavedSecurity.back();
		bool modifiedThisPath = false;

		if (backup && backup->hasDacl) {
			DWORD dw = GrantFullControlToSidOnPath(path.c_str(), appContainerSid);
			if (dw == ERROR_SUCCESS) {
				wprintf(L"[OK] Granted (F) to %ls\r\n", path.c_str());
				LogInfo(L"[Permissions] Granted FILE_ALL_ACCESS on %ls", path.c_str());
				modifiedThisPath = true;
			}
			else {
				wprintf(L"[Warn] Grant (F) failed on %ls (%lu)\r\n", path.c_str(), dw);
				LogWarn(L"[Permissions] Grant (F) failed on %ls (err=%lu)", path.c_str(), dw);
				++failedCount;
			}
		}

		if (PathLowIntegrity && backup && backup->hasSacl) {
			DWORD dw = SetLowIntegrityLabel(path.c_str());
			if (dw == ERROR_SUCCESS) {
				wprintf(L"[OK] Low Integrity set on %ls\r\n", path.c_str());
				LogInfo(L"[Permissions] Low Integrity set on %ls", path.c_str());
				modifiedThisPath = true;
			}
			else {
				wprintf(L"[Warn] Set Low Integrity failed on %ls (%lu)\r\n", path.c_str(), dw);
				if (dw == ERROR_ACCESS_DENIED)
					LogWarn(L"[Permissions] Set Low Integrity DENIED on %ls. Run elevated or set lowIntegrityOnPaths=false.", path.c_str());
				else
					LogWarn(L"[Permissions] Set Low Integrity failed on %ls (err=%lu)", path.c_str(), dw);
				++failedCount;
			}
		}

		if (modifiedThisPath) {
			InterlockedExchange(&g_PathAclModified, 1);
			++grantedCount;
		}
		else {
			if (!g_SavedSecurity.empty()) {
				auto& ss = g_SavedSecurity.back();
				if (ss.sdDacl) { LocalFree(ss.sdDacl); ss.sdDacl = nullptr; }
				if (ss.sdSacl) { LocalFree(ss.sdSacl); ss.sdSacl = nullptr; }
				g_SavedSecurity.pop_back();
			}
		}
	}

	LogInfo(L"[Permissions] Access grant summary: granted=%d, skipped=%d, failed=%d (total paths=%llu)",
		grantedCount, skippedCount, failedCount, (unsigned long long)AllowedPaths.size());

	// Grant read/execute on system paths (ReadOnlyAllowedPaths)
	if (!ReadOnlyAllowedPaths.empty()) {
		LogInfo(L"[Permissions] Granting read/execute to %llu read-only path(s)...", (unsigned long long)ReadOnlyAllowedPaths.size());
		int roGranted = 0, roSkipped = 0, roFailed = 0;

		for (const auto& path : ReadOnlyAllowedPaths) {
			DWORD attrs = GetFileAttributesW(path.c_str());
			if (attrs == INVALID_FILE_ATTRIBUTES) {
				LogWarn(L"[Permissions] Skip read-only path (not found): %ls (err=%lu)", path.c_str(), GetLastError());
				++roSkipped;
				continue;
			}
			if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
				LogWarn(L"[Permissions] Skip read-only path (not directory): %ls", path.c_str());
				++roSkipped;
				continue;
			}

			SaveOriginalSecurityForPath(path.c_str());
			SavedSecurity* backup = g_SavedSecurity.empty() ? nullptr : &g_SavedSecurity.back();

			if (backup && backup->hasDacl) {
				DWORD dw = GrantReadExecuteToSidOnPath(path.c_str(), appContainerSid);
				if (dw == ERROR_SUCCESS) {
					wprintf(L"[OK] Granted (RX) to %ls\r\n", path.c_str());
					LogInfo(L"[Permissions] Granted READ_EXECUTE on %ls", path.c_str());
					InterlockedExchange(&g_PathAclModified, 1);
					++roGranted;
				}
				else {
					wprintf(L"[Warn] Grant (RX) failed on %ls (%lu)\r\n", path.c_str(), dw);
					LogWarn(L"[Permissions] Grant (RX) failed on %ls (err=%lu)", path.c_str(), dw);
					// Clean up saved security since we didn't modify
					if (!g_SavedSecurity.empty()) {
						auto& ss = g_SavedSecurity.back();
						if (ss.sdDacl) { LocalFree(ss.sdDacl); ss.sdDacl = nullptr; }
						if (ss.sdSacl) { LocalFree(ss.sdSacl); ss.sdSacl = nullptr; }
						g_SavedSecurity.pop_back();
					}
					++roFailed;
				}
			}
			else {
				if (!g_SavedSecurity.empty()) {
					auto& ss = g_SavedSecurity.back();
					if (ss.sdDacl) { LocalFree(ss.sdDacl); ss.sdDacl = nullptr; }
					if (ss.sdSacl) { LocalFree(ss.sdSacl); ss.sdSacl = nullptr; }
					g_SavedSecurity.pop_back();
				}
				++roSkipped;
			}
		}

		LogInfo(L"[Permissions] Read-only grant summary: granted=%d, skipped=%d, failed=%d",
			roGranted, roSkipped, roFailed);
	}
}


// ========================================================================
// ConPTY Support
// ========================================================================
static bool InitConPtyApi() {
	if (g_ConPtyAvailable) return true;
	HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
	if (!hK32) {
		LogWarn(L"[ConPTY] GetModuleHandleW(kernel32.dll) failed.");
		return false;
	}
	g_pfnCreatePC = (FnCreatePseudoConsole)GetProcAddress(hK32, "CreatePseudoConsole");
	g_pfnClosePC = (FnClosePseudoConsole)GetProcAddress(hK32, "ClosePseudoConsole");
	g_ConPtyAvailable = (g_pfnCreatePC != nullptr && g_pfnClosePC != nullptr);
	if (!g_ConPtyAvailable) {
		LogWarn(L"[ConPTY] CreatePseudoConsole not available on this OS.");
	}
	else {
		LogDebug(L"[ConPTY] API loaded: CreatePseudoConsole=%p, ClosePseudoConsole=%p",
			(void*)g_pfnCreatePC, (void*)g_pfnClosePC);
	}
	return g_ConPtyAvailable;
}

static COORD GetCurrentConsoleSize() {
	CONSOLE_SCREEN_BUFFER_INFO csbi{};
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hOut, &csbi)) {
		COORD sz;
		sz.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		sz.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
		LogDebug(L"[ConPTY] Console size: %dx%d", sz.X, sz.Y);
		return sz;
	}
	COORD fallback;
	fallback.X = 120;
	fallback.Y = 30;
	LogDebug(L"[ConPTY] Using fallback console size: %dx%d", fallback.X, fallback.Y);
	return fallback;
}

struct InputRelayCtx {
	HANDLE hPipeWrite;
	HANDLE hStopEvent;
};

static DWORD WINAPI ConPtyInputRelay(LPVOID param) {
	InputRelayCtx* ctx = static_cast<InputRelayCtx*>(param);
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	char buf[4096];
	DWORD totalRelayed = 0;
	for (;;) {
		HANDLE waits[2] = { hStdin, ctx->hStopEvent };
		DWORD wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
		if (wr != WAIT_OBJECT_0) break;
		DWORD bytesRead = 0;
		if (!ReadFile(hStdin, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0) break;
		DWORD totalWritten = 0;
		while (totalWritten < bytesRead) {
			DWORD written = 0;
			if (!WriteFile(ctx->hPipeWrite, buf + totalWritten,
				bytesRead - totalWritten, &written, nullptr)) goto done;
			totalWritten += written;
		}
		totalRelayed += bytesRead;
	}
done:
	LogDebug(L"[ConPTY] Input relay thread exiting. Total bytes relayed: %lu", totalRelayed);
	return 0;
}

static DWORD WINAPI ConPtyOutputRelay(LPVOID param) {
	HANDLE hPipeRead = static_cast<HANDLE>(param);
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	char buf[4096];
	DWORD totalRelayed = 0;
	for (;;) {
		DWORD bytesRead = 0;
		if (!ReadFile(hPipeRead, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0) break;
		DWORD totalWritten = 0;
		while (totalWritten < bytesRead) {
			DWORD written = 0;
			if (!WriteFile(hStdout, buf + totalWritten,
				bytesRead - totalWritten, &written, nullptr)) goto done;
			totalWritten += written;
		}
		totalRelayed += bytesRead;
	}
done:
	LogDebug(L"[ConPTY] Output relay thread exiting. Total bytes relayed: %lu", totalRelayed);
	return 0;
}
static std::wstring GetExeDir() {
	wchar_t exePath[MAX_PATH] = {};
	DWORD length = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return L""; // Return an empty string if the path cannot be retrieved
	}

	std::wstring dir(exePath, length);
	size_t pos = dir.find_last_of(L"\\/");
	if (pos != std::wstring::npos) {
		dir = dir.substr(0, pos + 1); // Extract the directory part
	}
	else {
		dir = L".\\"; // Default to current directory
	}

	return dir;
}

// ========================================================================
// Bun Standalone Virtual Drive (B:\~BUN) Support
// ========================================================================
// Bun standalone executables embed native DLLs (like opentui) and serve
// them through a virtual B: drive created via DefineDosDeviceW() at startup.
// AppContainer blocks this call, so the child gets error 126 on LoadLibrary.
//
// Solution: the PARENT process (not sandboxed) extracts the embedded DLL
// from the opencode.exe binary, places it in a real staging directory that
// mirrors B:\~BUN\root\<dllname>, then uses DefineDosDeviceW() to create
// a session-visible B: drive mapping before launching the child.
// ========================================================================

// Search binary for ASCII filename matching "opentui-XXXX.dll"
static std::wstring FindDllNameInBinary(const BYTE* data, size_t dataSize) {
	LogDebug(L"[BunVFS] Scanning %llu bytes for DLL name pattern 'opentui-*.dll'...",
		(unsigned long long)dataSize);
	const char* pat = "opentui-";
	size_t patLen = 8;
	int candidateCount = 0;

	for (size_t i = 0; i + patLen + 4 < dataSize; ++i) {
		if (memcmp(data + i, pat, patLen) != 0) continue;

		++candidateCount;
		size_t j = i + patLen;
		while (j < dataSize && j - i < 80) {
			BYTE ch = data[j];
			if (ch == '.') break;
			if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
				++j;
			}
			else {
				break;
			}
		}

		if (j + 4 <= dataSize && memcmp(data + j, ".dll", 4) == 0) {
			size_t nameLen = (j + 4) - i;
			std::string name(reinterpret_cast<const char*>(data + i), nameLen);
			std::wstring wname(name.begin(), name.end());
			LogInfo(L"[BunVFS] Found DLL name at offset 0x%llX: '%ls' (scanned %d candidates)",
				(unsigned long long)i, wname.c_str(), candidateCount);
			return wname;
		}
		else {
			LogDebug(L"[BunVFS] Candidate #%d at offset 0x%llX did not end with '.dll', skipping.",
				candidateCount, (unsigned long long)i);
		}
	}

	LogWarn(L"[BunVFS] DLL name pattern not found after scanning %d candidates in %llu bytes.",
		candidateCount, (unsigned long long)dataSize);
	return L"";
}

// Convert an RVA (Relative Virtual Address) to a file offset using the section table.
// Returns 0 on failure. The PE base pointer must point to a valid MZ header.
static DWORD RvaToFileOffset(const BYTE* peBase, size_t peSize, DWORD rva) {
	if (peSize < 0x200 || rva == 0) return 0;

	DWORD peOff = *reinterpret_cast<const DWORD*>(peBase + 0x3C);
	if (peOff + 4 + 20 > peSize) return 0;

	size_t coffOff = peOff + 4;
	WORD numSections = *reinterpret_cast<const WORD*>(peBase + coffOff + 2);
	WORD optSize = *reinterpret_cast<const WORD*>(peBase + coffOff + 16);
	size_t secTableOff = coffOff + 20 + optSize;

	if (numSections > 96 || secTableOff + numSections * 40 > peSize) return 0;

	for (WORD s = 0; s < numSections; ++s) {
		size_t sh = secTableOff + s * 40;
		DWORD secVA = *reinterpret_cast<const DWORD*>(peBase + sh + 12);
		DWORD secRawSize = *reinterpret_cast<const DWORD*>(peBase + sh + 16);
		DWORD secRawPtr = *reinterpret_cast<const DWORD*>(peBase + sh + 20);
		DWORD secVSize = *reinterpret_cast<const DWORD*>(peBase + sh + 8);

		// Use the larger of VirtualSize and SizeOfRawData for bounds
		DWORD secExtent = (secRawSize > secVSize) ? secRawSize : secVSize;
		if (rva >= secVA && rva < secVA + secExtent) {
			DWORD offset = secRawPtr + (rva - secVA);
			if (offset < peSize) return offset;
		}
	}

	// RVA might be in headers (before first section)
	DWORD sizeOfHeaders = 0;
	size_t optOff = coffOff + 20;
	if (optOff + 64 <= peSize) {
		sizeOfHeaders = *reinterpret_cast<const DWORD*>(peBase + optOff + 60);
	}
	if (rva < sizeOfHeaders && rva < peSize) return rva;

	return 0;
}

// Check if a PE DLL (raw bytes in memory) exports a specific symbol name.
// Returns true if the symbol is found in the export name table.
// Also returns the total number of exported names via outExportCount (if non-null).
static bool PEDllExportsSymbol(const BYTE* peBase, size_t peSize,
	const char* symbolName,
	int* outExportCount = nullptr) {
	if (outExportCount) *outExportCount = 0;
	if (!peBase || peSize < 0x200 || !symbolName) return false;
	if (peBase[0] != 'M' || peBase[1] != 'Z') return false;

	DWORD peOff = *reinterpret_cast<const DWORD*>(peBase + 0x3C);
	if (peOff + 4 + 20 > peSize) return false;

	size_t coffOff = peOff + 4;
	WORD optSize = *reinterpret_cast<const WORD*>(peBase + coffOff + 16);
	size_t optOff = coffOff + 20;
	if (optOff + optSize > peSize) return false;

	WORD magic = *reinterpret_cast<const WORD*>(peBase + optOff);
	DWORD numDataDirs = 0;
	size_t dataDirOff = 0;
	if (magic == 0x010B) { // PE32
		if (optSize < 96) return false;
		numDataDirs = *reinterpret_cast<const DWORD*>(peBase + optOff + 92);
		dataDirOff = optOff + 96;
	}
	else if (magic == 0x020B) { // PE32+
		if (optSize < 112) return false;
		numDataDirs = *reinterpret_cast<const DWORD*>(peBase + optOff + 108);
		dataDirOff = optOff + 112;
	}
	else {
		return false;
	}
	if (numDataDirs > 16) numDataDirs = 16;

	// Export directory is data dir index 0
	if (numDataDirs < 1) return false;
	DWORD exportRVA = *reinterpret_cast<const DWORD*>(peBase + dataDirOff);
	DWORD exportSize = *reinterpret_cast<const DWORD*>(peBase + dataDirOff + 4);
	if (exportRVA == 0 || exportSize == 0) {
		LogDebug(L"[BunVFS/Export] No export directory (RVA=0x%lX, size=0x%lX)", exportRVA, exportSize);
		return false;
	}

	DWORD exportFileOff = RvaToFileOffset(peBase, peSize, exportRVA);
	if (exportFileOff == 0 || exportFileOff + 40 > peSize) {
		LogDebug(L"[BunVFS/Export] Export directory RVA 0x%lX -> file offset 0x%lX (invalid or out of bounds)",
			exportRVA, exportFileOff);
		return false;
	}

	// IMAGE_EXPORT_DIRECTORY structure (40 bytes)
	// Offset 24: NumberOfNames (DWORD)
	// Offset 32: AddressOfNames (DWORD RVA -> array of RVAs to name strings)
	DWORD numberOfNames = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 24);
	DWORD namesRVA = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 32);

	// Also read DLL name from export dir
	DWORD dllNameRVA = *reinterpret_cast<const DWORD*>(peBase + exportFileOff + 12);
	if (dllNameRVA > 0) {
		DWORD dllNameOff = RvaToFileOffset(peBase, peSize, dllNameRVA);
		if (dllNameOff > 0 && dllNameOff + 1 < peSize) {
			const char* dn = reinterpret_cast<const char*>(peBase + dllNameOff);
			size_t maxLen = peSize - dllNameOff;
			size_t len = strnlen(dn, maxLen > 260 ? 260 : maxLen);
			LogDebug(L"[BunVFS/Export] Export DLL name: '%.260S'", dn);
		}
	}

	LogDebug(L"[BunVFS/Export] Export directory: RVA=0x%lX, fileOff=0x%lX, numberOfNames=%lu, namesRVA=0x%lX",
		exportRVA, exportFileOff, numberOfNames, namesRVA);

	if (outExportCount) *outExportCount = static_cast<int>(numberOfNames);

	if (numberOfNames == 0 || namesRVA == 0) return false;
	if (numberOfNames > 100000) {
		LogWarn(L"[BunVFS/Export] Suspicious export count: %lu", numberOfNames);
		return false;
	}

	DWORD namesFileOff = RvaToFileOffset(peBase, peSize, namesRVA);
	if (namesFileOff == 0 || namesFileOff + numberOfNames * 4 > peSize) {
		LogDebug(L"[BunVFS/Export] Names array out of bounds: fileOff=0x%lX", namesFileOff);
		return false;
	}

	size_t symbolLen = strlen(symbolName);
	bool found = false;
	int printedCount = 0;

	for (DWORD i = 0; i < numberOfNames; ++i) {
		DWORD nameRVA = *reinterpret_cast<const DWORD*>(peBase + namesFileOff + i * 4);
		DWORD nameOff = RvaToFileOffset(peBase, peSize, nameRVA);
		if (nameOff == 0 || nameOff >= peSize) continue;

		const char* name = reinterpret_cast<const char*>(peBase + nameOff);
		size_t maxLen = peSize - nameOff;
		size_t len = strnlen(name, maxLen > 512 ? 512 : maxLen);

		// Log first 20 exports and any match
		if (printedCount < 20) {
			LogDebug(L"[BunVFS/Export]   [%lu] '%.260S'", i, name);
			++printedCount;
		}
		else if (printedCount == 20) {
			LogDebug(L"[BunVFS/Export]   ... (%lu more exports not shown)", numberOfNames - 20);
			++printedCount;
		}

		if (len == symbolLen && memcmp(name, symbolName, symbolLen) == 0) {
			LogInfo(L"[BunVFS/Export] *** Found target symbol '%S' at export index %lu ***", symbolName, i);
			found = true;
			// Don't break - continue logging to show full picture
		}
	}

	if (!found) {
		LogWarn(L"[BunVFS/Export] Symbol '%S' NOT found among %lu exports.", symbolName, numberOfNames);
	}
	return found;
}

// Thoroughly validate an embedded PE DLL and compute its COMPLETE file size.
// This accounts for:
//   1) PE headers (SizeOfHeaders)
//   2) All section raw data (PointerToRawData + SizeOfRawData)
//   3) Certificate/Authenticode data (IMAGE_DIRECTORY_ENTRY_SECURITY, index 4)
//   4) Debug directory raw data (index 6)
//   5) FileAlignment alignment
// Returns 0 if the region is not a valid PE DLL.
static size_t ValidatePEDllAndGetCompleteSize(const BYTE* base, size_t maxLen) {
	if (maxLen < 0x200) {
		return 0;
	}
	if (base[0] != 'M' || base[1] != 'Z') return 0;

	DWORD peOff = *reinterpret_cast<const DWORD*>(base + 0x3C);
	if (peOff < 0x40 || peOff > 0x10000) return 0;
	if (peOff + 4 + 20 > maxLen) return 0;

	if (base[peOff] != 'P' || base[peOff + 1] != 'E' ||
		base[peOff + 2] != 0 || base[peOff + 3] != 0) return 0;

	size_t coffOff = peOff + 4;
	WORD machine = *reinterpret_cast<const WORD*>(base + coffOff + 0);
	WORD numSections = *reinterpret_cast<const WORD*>(base + coffOff + 2);
	WORD optHeaderSize = *reinterpret_cast<const WORD*>(base + coffOff + 16);
	WORD characteristics = *reinterpret_cast<const WORD*>(base + coffOff + 18);

	LogDebug(L"[BunVFS/PE] COFF header: machine=0x%04X, sections=%u, optHdrSize=%u, chars=0x%04X",
		machine, numSections, optHeaderSize, characteristics);

	if (!(characteristics & 0x2000)) return 0; //IMAGE_FILE_DLL
	if (machine != 0x014C && machine != 0x8664) return 0;
	if (numSections == 0 || numSections > 96) return 0;
	if (optHeaderSize < 96) return 0;

	size_t optOff = coffOff + 20;
	if (optOff + optHeaderSize > maxLen) return 0;

	WORD optMagic = *reinterpret_cast<const WORD*>(base + optOff);
	bool isPE32Plus = (optMagic == 0x020B);
	bool isPE32 = (optMagic == 0x010B);
	if (!isPE32 && !isPE32Plus) return 0;

	LogDebug(L"[BunVFS/PE] Format: %ls", isPE32Plus ? L"PE32+ (64-bit)" : L"PE32 (32-bit)");

	if (isPE32Plus && machine != 0x8664) return 0;
	if (isPE32 && machine != 0x014C) return 0;

	DWORD sizeOfHeaders = *reinterpret_cast<const DWORD*>(base + optOff + 60);
	DWORD fileAlignment = *reinterpret_cast<const DWORD*>(base + optOff + 36);
	if (fileAlignment == 0 || (fileAlignment & (fileAlignment - 1)) != 0) return 0;
	if (fileAlignment < 512 || fileAlignment > 65536) return 0;

	// SizeOfImage from optional header (useful for sanity checks)
	DWORD sizeOfImage = 0;
	if (isPE32) {
		sizeOfImage = *reinterpret_cast<const DWORD*>(base + optOff + 56);
	}
	else {
		sizeOfImage = *reinterpret_cast<const DWORD*>(base + optOff + 56);
	}

	LogDebug(L"[BunVFS/PE] SizeOfHeaders=0x%lX, FileAlignment=0x%lX, SizeOfImage=0x%lX",
		sizeOfHeaders, fileAlignment, sizeOfImage);

	DWORD numDataDirs = 0;
	size_t dataDirOff = 0;
	if (isPE32) {
		if (optHeaderSize < 96) return 0;
		numDataDirs = *reinterpret_cast<const DWORD*>(base + optOff + 92);
		dataDirOff = optOff + 96;
	}
	else {
		if (optHeaderSize < 112) return 0;
		numDataDirs = *reinterpret_cast<const DWORD*>(base + optOff + 108);
		dataDirOff = optOff + 112;
	}
	if (numDataDirs > 16) numDataDirs = 16;

	LogDebug(L"[BunVFS/PE] NumberOfRvaAndSizes=%lu", numDataDirs);

	size_t sectionTableOff = optOff + optHeaderSize;
	if (sectionTableOff + numSections * 40 > maxLen) return 0;

	// === Compute complete file size ===
	size_t totalSize = sizeOfHeaders;

	// 1) End of all section raw data
	for (WORD s = 0; s < numSections; ++s) {
		size_t shOff = sectionTableOff + s * 40;
		char secName[9] = {};
		memcpy(secName, base + shOff, 8);
		DWORD rawSize = *reinterpret_cast<const DWORD*>(base + shOff + 16);
		DWORD rawPtr = *reinterpret_cast<const DWORD*>(base + shOff + 20);

		LogDebug(L"[BunVFS/PE]   Section[%u] '%.8S': RawSize=0x%lX, RawPtr=0x%lX",
			s, secName, rawSize, rawPtr);

		if (rawSize > 0 && rawPtr > 0) {
			size_t end = static_cast<size_t>(rawPtr) + rawSize;
			if (end > maxLen) return 0;
			if (end > totalSize) totalSize = end;
		}
	}

	LogDebug(L"[BunVFS/PE] Size after sections: 0x%llX", (unsigned long long)totalSize);

	// 2) Certificate / Authenticode table (index 4) - uses FILE OFFSET, not RVA
	if (numDataDirs > 4) {
		size_t certEntryOff = dataDirOff + 4 * 8;
		if (certEntryOff + 8 <= optOff + optHeaderSize) {
			DWORD certFileOffset = *reinterpret_cast<const DWORD*>(base + certEntryOff);
			DWORD certSize = *reinterpret_cast<const DWORD*>(base + certEntryOff + 4);
			if (certFileOffset > 0 && certSize > 0) {
				size_t certEnd = static_cast<size_t>(certFileOffset) + certSize;
				if (certEnd > maxLen) return 0;
				if (certEnd > totalSize) totalSize = certEnd;
				LogInfo(L"[BunVFS/PE] Certificate data: offset=0x%lX, size=0x%lX, end=0x%llX",
					certFileOffset, certSize, (unsigned long long)certEnd);
			}
		}
	}

	// 3) Debug directory (index 6) - entries may have PointerToRawData outside sections
	if (numDataDirs > 6) {
		size_t dbgEntryOff = dataDirOff + 6 * 8;
		if (dbgEntryOff + 8 <= optOff + optHeaderSize) {
			DWORD dbgRVA = *reinterpret_cast<const DWORD*>(base + dbgEntryOff);
			DWORD dbgSize = *reinterpret_cast<const DWORD*>(base + dbgEntryOff + 4);
			if (dbgRVA > 0 && dbgSize > 0) {
				DWORD dbgFileOff = RvaToFileOffset(base, maxLen, dbgRVA);
				if (dbgFileOff > 0) {
					// Each IMAGE_DEBUG_DIRECTORY is 28 bytes
					DWORD numEntries = dbgSize / 28;
					LogDebug(L"[BunVFS/PE] Debug directory: RVA=0x%lX, fileOff=0x%lX, entries=%lu",
						dbgRVA, dbgFileOff, numEntries);
					for (DWORD d = 0; d < numEntries && dbgFileOff + d * 28 + 28 <= maxLen; ++d) {
						size_t entOff = dbgFileOff + d * 28;
						DWORD dbgDataSize = *reinterpret_cast<const DWORD*>(base + entOff + 16);
						DWORD dbgDataPtr = *reinterpret_cast<const DWORD*>(base + entOff + 24);
						if (dbgDataSize > 0 && dbgDataPtr > 0) {
							size_t dbgEnd = static_cast<size_t>(dbgDataPtr) + dbgDataSize;
							if (dbgEnd <= maxLen && dbgEnd > totalSize) {
								LogDebug(L"[BunVFS/PE]   Debug entry[%lu]: rawPtr=0x%lX, size=0x%lX, extends total to 0x%llX",
									d, dbgDataPtr, dbgDataSize, (unsigned long long)dbgEnd);
								totalSize = dbgEnd;
							}
						}
					}
				}
			}
		}
	}

	LogDebug(L"[BunVFS/PE] Size after cert+debug: 0x%llX", (unsigned long long)totalSize);

	// 4) Align total size up to FileAlignment
	size_t unalignedSize = totalSize;
	if (fileAlignment > 1) {
		totalSize = (totalSize + fileAlignment - 1) & ~(static_cast<size_t>(fileAlignment) - 1);
		if (totalSize > maxLen) totalSize = maxLen;
	}

	if (totalSize != unalignedSize) {
		LogDebug(L"[BunVFS/PE] Size after alignment to 0x%lX: 0x%llX (was 0x%llX)",
			fileAlignment, (unsigned long long)totalSize, (unsigned long long)unalignedSize);
	}

	if (totalSize < 4096) return 0;

	LogInfo(L"[BunVFS/PE] Validated DLL: %ls, %u sections, computed size=%llu bytes (0x%llX)",
		isPE32Plus ? L"PE32+(x64)" : L"PE32(x86)",
		numSections, (unsigned long long)totalSize, (unsigned long long)totalSize);

	return totalSize;
}

// After extraction, verify the DLL is loadable by checking key PE structures
// and also verifying that expected exports (like "setLogCallback") exist.
static bool VerifyExtractedDll(const std::wstring& dllPath, bool checkExports = true) {
	LogInfo(L"[BunVFS/Verify] Verifying extracted DLL: %ls", dllPath.c_str());

	HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		LogError(L"[BunVFS/Verify] Cannot open DLL file: %ls (err=%lu)", dllPath.c_str(), GetLastError());
		return false;
	}

	LARGE_INTEGER li{};
	GetFileSizeEx(hFile, &li);
	size_t fileSize = static_cast<size_t>(li.QuadPart);

	LogDebug(L"[BunVFS/Verify] File size: %llu bytes (0x%llX)",
		(unsigned long long)fileSize, (unsigned long long)fileSize);

	if (fileSize < 4096) {
		CloseHandle(hFile);
		LogWarn(L"[BunVFS/Verify] DLL too small: %llu bytes (minimum 4096)", (unsigned long long)fileSize);
		return false;
	}

	HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMap) {
		LogError(L"[BunVFS/Verify] CreateFileMappingW failed: err=%lu", GetLastError());
		CloseHandle(hFile);
		return false;
	}

	const BYTE* base = static_cast<const BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
	if (!base) {
		LogError(L"[BunVFS/Verify] MapViewOfFile failed: err=%lu", GetLastError());
		CloseHandle(hMap);
		CloseHandle(hFile);
		return false;
	}

	bool valid = true;

	// 1) MZ + PE signature
	if (base[0] != 'M' || base[1] != 'Z') {
		LogError(L"[BunVFS/Verify] FAIL: Missing MZ signature (got 0x%02X 0x%02X)", base[0], base[1]);
		valid = false;
		goto done;
	}
	LogDebug(L"[BunVFS/Verify] PASS: MZ signature present");

	{
		DWORD peOff = *reinterpret_cast<const DWORD*>(base + 0x3C);
		if (peOff + 4 > fileSize) {
			LogError(L"[BunVFS/Verify] FAIL: e_lfanew=0x%lX exceeds file size", peOff);
			valid = false;
			goto done;
		}
		if (base[peOff] != 'P' || base[peOff + 1] != 'E') {
			LogError(L"[BunVFS/Verify] FAIL: No PE signature at offset 0x%lX", peOff);
			valid = false;
			goto done;
		}
		LogDebug(L"[BunVFS/Verify] PASS: PE signature at offset 0x%lX", peOff);

		// 2) DLL flag
		WORD chars = *reinterpret_cast<const WORD*>(base + peOff + 4 + 18);
		if (!(chars & 0x2000)) {
			LogError(L"[BunVFS/Verify] FAIL: IMAGE_FILE_DLL flag not set (chars=0x%04X)", chars);
			valid = false;
			goto done;
		}
		LogDebug(L"[BunVFS/Verify] PASS: DLL flag set (chars=0x%04X)", chars);

		// 3) All sections' raw data must be within file bounds
		WORD numSections = *reinterpret_cast<const WORD*>(base + peOff + 4 + 2);
		WORD optSize = *reinterpret_cast<const WORD*>(base + peOff + 4 + 16);
		size_t secOff = peOff + 4 + 20 + optSize;

		LogDebug(L"[BunVFS/Verify] Checking %u sections for file bounds...", numSections);

		for (WORD s = 0; s < numSections && secOff + s * 40 + 40 <= fileSize; ++s) {
			size_t sh = secOff + s * 40;
			char secName[9] = {};
			memcpy(secName, base + sh, 8);
			DWORD rawSize = *reinterpret_cast<const DWORD*>(base + sh + 16);
			DWORD rawPtr = *reinterpret_cast<const DWORD*>(base + sh + 20);
			if (rawSize > 0 && rawPtr > 0) {
				size_t end = static_cast<size_t>(rawPtr) + rawSize;
				if (end > fileSize) {
					LogError(L"[BunVFS/Verify] FAIL: Section[%u] '%.8S' extends beyond file: "
						L"RawPtr=0x%lX + RawSize=0x%lX = 0x%llX > fileSize=0x%llX",
						s, secName, rawPtr, rawSize, (unsigned long long)end, (unsigned long long)fileSize);
					valid = false;
					goto done;
				}
				LogDebug(L"[BunVFS/Verify]   Section[%u] '%.8S': OK (end=0x%llX)", s, secName, (unsigned long long)end);
			}
		}
		LogDebug(L"[BunVFS/Verify] PASS: All sections within file bounds");

		// 4) Check export directory and verify expected symbols
		if (checkExports) {
			int exportCount = 0;
			bool hasSetLogCallback = PEDllExportsSymbol(base, fileSize, "setLogCallback", &exportCount);

			if (exportCount == 0) {
				LogWarn(L"[BunVFS/Verify] WARNING: DLL has NO exports at all - likely wrong PE or truncated!");
				valid = false;
				goto done;
			}

			LogInfo(L"[BunVFS/Verify] DLL has %d exports, setLogCallback=%ls",
				exportCount, hasSetLogCallback ? L"FOUND" : L"NOT FOUND");

			if (!hasSetLogCallback) {
				LogError(L"[BunVFS/Verify] FAIL: Required symbol 'setLogCallback' not found in exports.");
				LogError(L"[BunVFS/Verify]   This PE DLL is likely the wrong embedded image.");
				valid = false;
				goto done;
			}
			LogInfo(L"[BunVFS/Verify] PASS: Required export 'setLogCallback' present");
		}

		// 5) Check certificate data bounds
		size_t optOff2 = peOff + 4 + 20;
		WORD magic = *reinterpret_cast<const WORD*>(base + optOff2);
		DWORD numDD = 0;
		size_t ddOff = 0;
		if (magic == 0x010B) { numDD = *reinterpret_cast<const DWORD*>(base + optOff2 + 92); ddOff = optOff2 + 96; }
		else if (magic == 0x020B) { numDD = *reinterpret_cast<const DWORD*>(base + optOff2 + 108); ddOff = optOff2 + 112; }
		if (numDD > 16) numDD = 16;

		if (numDD > 4 && ddOff + 4 * 8 + 8 <= fileSize) {
			DWORD certOff = *reinterpret_cast<const DWORD*>(base + ddOff + 4 * 8);
			DWORD certSize = *reinterpret_cast<const DWORD*>(base + ddOff + 4 * 8 + 4);
			if (certOff > 0 && certSize > 0) {
				size_t certEnd = static_cast<size_t>(certOff) + certSize;
				if (certEnd > fileSize) {
					LogError(L"[BunVFS/Verify] FAIL: Certificate data extends beyond file");
					valid = false;
					goto done;
				}
				LogDebug(L"[BunVFS/Verify] Certificate: offset=0x%lX, size=0x%lX", certOff, certSize);
			}
		}
	}

done:
	UnmapViewOfFile(base);
	CloseHandle(hMap);
	CloseHandle(hFile);

	if (valid) {
		LogInfo(L"[BunVFS/Verify] ===== DLL VERIFICATION PASSED ===== %ls (%llu bytes)",
			dllPath.c_str(), (unsigned long long)fileSize);
	}
	else {
		LogError(L"[BunVFS/Verify] ===== DLL VERIFICATION FAILED ===== %ls", dllPath.c_str());
	}
	return valid;
}

// Candidate PE DLL found during scan
struct PECandidate {
	size_t offset;
	size_t size;
	bool hasTargetExport;
	int exportCount;
};

// Scan the exe binary for ALL valid PE DLL candidates and pick the best one.
// "Best" = has the target export (setLogCallback) and largest export count.
static bool ScanAndExtractBestDll(const BYTE* data, size_t dataSize,
	const std::wstring& dllName, const std::wstring& outPath) {
	LogInfo(L"[BunVFS] Scanning %llu bytes for embedded PE DLLs...", (unsigned long long)dataSize);

	std::vector<PECandidate> candidates;
	// Scan at 1-byte alignment: Bun embeds DLLs at arbitrary offsets
	const size_t step = 1;

	for (size_t i = 0; i + 0x200 < dataSize; i += step) {
		if (data[i] != 'M' || data[i + 1] != 'Z') continue;

		size_t remaining = dataSize - i;
		size_t peSize = ValidatePEDllAndGetCompleteSize(data + i, remaining);
		if (peSize == 0) continue;

		int exportCount = 0;
		bool hasTarget = PEDllExportsSymbol(data + i, peSize, "setLogCallback", &exportCount);

		LogInfo(L"[BunVFS] PE candidate at offset 0x%llX: size=%llu, exports=%d, hasSetLogCallback=%ls",
			(unsigned long long)i, (unsigned long long)peSize, exportCount,
			hasTarget ? L"YES" : L"NO");

		candidates.push_back(PECandidate{ i, peSize, hasTarget, exportCount });
	}

	if (candidates.empty()) {
		LogWarn(L"[BunVFS] No valid PE DLL candidates found in binary.");
		return false;
	}

	LogInfo(L"[BunVFS] Found %llu PE DLL candidate(s).", (unsigned long long)candidates.size());

	// Pick best: prefer hasTargetExport, then highest exportCount
	size_t bestIdx = 0;
	for (size_t i = 1; i < candidates.size(); ++i) {
		auto& best = candidates[bestIdx];
		auto& cur = candidates[i];
		if (cur.hasTargetExport && !best.hasTargetExport) { bestIdx = i; continue; }
		if (!cur.hasTargetExport && best.hasTargetExport) continue;
		if (cur.exportCount > best.exportCount) bestIdx = i;
	}

	auto& chosen = candidates[bestIdx];
	LogInfo(L"[BunVFS] Selected candidate #%llu: offset=0x%llX, size=%llu, exports=%d",
		(unsigned long long)bestIdx, (unsigned long long)chosen.offset,
		(unsigned long long)chosen.size, chosen.exportCount);

	// Write to output file
	HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hOut == INVALID_HANDLE_VALUE) {
		LogError(L"[BunVFS] Failed to create output file: %ls (err=%lu)", outPath.c_str(), GetLastError());
		return false;
	}

	const BYTE* src = data + chosen.offset;
	size_t remaining = chosen.size;
	while (remaining > 0) {
		DWORD toWrite = (remaining > 0x10000000) ? 0x10000000 : static_cast<DWORD>(remaining);
		DWORD written = 0;
		if (!WriteFile(hOut, src, toWrite, &written, nullptr)) {
			LogError(L"[BunVFS] WriteFile failed: err=%lu", GetLastError());
			CloseHandle(hOut);
			DeleteFileW(outPath.c_str());
			return false;
		}
		src += written;
		remaining -= written;
	}
	CloseHandle(hOut);

	LogInfo(L"[BunVFS] Extracted %llu bytes to: %ls", (unsigned long long)chosen.size, outPath.c_str());
	return true;
}

static void SetupBunVirtualDrive() {
	if (!ExeToLaunch) return;

	std::wstring imagePath = ParseImagePathFromCommandLine(ExeToLaunch);
	if (imagePath.empty()) return;

	// Only set up for bun-based or opencode invocations
	bool isBun = LooksLikeBunImage(imagePath) || CommandLineMentionsBun(ExeToLaunch);
	bool isOpenCode = LooksLikeOpenCodeImage(imagePath);
	if (!isBun && !isOpenCode) {
		LogDebug(L"[BunVFS] Not a Bun/OpenCode invocation, skipping VFS setup.");
		return;
	}

	LogInfo(L"[BunVFS] Setting up virtual drive for: %ls", imagePath.c_str());

	// Map the file into memory
	HANDLE hFile = CreateFileW(imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		LogWarn(L"[BunVFS] Cannot open exe for scanning: %ls (err=%lu)", imagePath.c_str(), GetLastError());
		return;
	}

	LARGE_INTEGER li{};
	GetFileSizeEx(hFile, &li);
	size_t fileSize = static_cast<size_t>(li.QuadPart);

	HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMap) {
		LogWarn(L"[BunVFS] CreateFileMappingW failed: err=%lu", GetLastError());
		CloseHandle(hFile);
		return;
	}

	const BYTE* data = static_cast<const BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
	if (!data) {
		LogWarn(L"[BunVFS] MapViewOfFile failed: err=%lu", GetLastError());
		CloseHandle(hMap);
		CloseHandle(hFile);
		return;
	}

	// Find the DLL name embedded in the binary
	std::wstring dllName = FindDllNameInBinary(data, fileSize);
	if (dllName.empty()) {
		LogInfo(L"[BunVFS] No embedded opentui DLL name found. Skipping VFS setup.");
		UnmapViewOfFile(data);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return;
	}

	// Create staging directory: <exeDir>\bun_vfs_staging\~BUN\root
	std::wstring exeDir = GetExeDir();
	g_BunStagingDir = JoinPath(exeDir, L"bun_vfs_staging");
	std::wstring bunDir = JoinPath(g_BunStagingDir, L"~BUN");
	std::wstring rootDir = JoinPath(bunDir, L"root");

	CreateDirectoryW(g_BunStagingDir.c_str(), nullptr);
	CreateDirectoryW(bunDir.c_str(), nullptr);
	CreateDirectoryW(rootDir.c_str(), nullptr);

	std::wstring dllPath = JoinPath(rootDir, dllName);

	// Extract the DLL
	bool extracted = ScanAndExtractBestDll(data, fileSize, dllName, dllPath);

	UnmapViewOfFile(data);
	CloseHandle(hMap);
	CloseHandle(hFile);

	if (!extracted) {
		LogWarn(L"[BunVFS] DLL extraction failed. VFS will not be set up.");
		return;
	}

	// Verify the extracted DLL
	if (!VerifyExtractedDll(dllPath, true)) {
		LogError(L"[BunVFS] Extracted DLL verification failed. Deleting and aborting.");
		DeleteFileW(dllPath.c_str());
		return;
	}

	// Map B: drive to the staging directory
	g_BunDriveTarget = g_BunStagingDir;
	if (DefineDosDeviceW(DDD_NO_BROADCAST_SYSTEM, L"B:", g_BunDriveTarget.c_str())) {
		g_BunDriveMapped = true;
		LogInfo(L"[BunVFS] Mapped B: -> %ls", g_BunDriveTarget.c_str());

		// Add staging dir to allowed paths so AppContainer can traverse B:\~BUN\root
		if (AddAllowedPathUnique(g_BunStagingDir)) {
			LogInfo(L"[BunVFS] Auto-allowed path: %ls", g_BunStagingDir.c_str());
		}
	}
	else {
		LogError(L"[BunVFS] DefineDosDeviceW failed: err=%lu", GetLastError());
	}
}

static void CleanupBunVirtualDrive() {
	if (InterlockedCompareExchange(&g_BunCleanupDone, 1, 0) != 0) return;

	if (g_BunDriveMapped) {
		if (DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_NO_BROADCAST_SYSTEM | DDD_EXACT_MATCH_ON_REMOVE,
			L"B:", g_BunDriveTarget.c_str())) {
			LogInfo(L"[BunVFS] Removed B: drive mapping.");
		}
		else {
			LogWarn(L"[BunVFS] Failed to remove B: drive mapping: err=%lu", GetLastError());
		}
		g_BunDriveMapped = false;
	}

	if (!g_BunStagingDir.empty() && DirectoryExists(g_BunStagingDir)) {
		DWORD dw = DeleteTreeNoFollow(g_BunStagingDir);
		if (dw == ERROR_SUCCESS) {
			LogInfo(L"[BunVFS] Cleaned up staging dir: %ls", g_BunStagingDir.c_str());
		}
		else {
			LogWarn(L"[BunVFS] Failed to clean staging dir: %ls (err=%lu)", g_BunStagingDir.c_str(), dw);
		}
	}
}

// ========================================================================
// INI Config File Parser
// ========================================================================
static bool IsBoolTrue(const std::wstring& val) {
	std::wstring v = ToLowerCopy(TrimCopy(val));
	return v == L"true" || v == L"1" || v == L"yes";
}

static bool LoadConfigFromIni() {
	std::wstring iniPath = GetExeDir() + L"config.ini";

	DWORD attrs = GetFileAttributesW(iniPath.c_str());
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		wprintf(L"[Error] config.ini not found: %ls\r\n", iniPath.c_str());
		return false;
	}

	LogInfo(L"[Config] Loading config from: %ls", iniPath.c_str());

	// Read entire file as UTF-8
	HANDLE hFile = CreateFileW(iniPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"[Error] Cannot open config.ini: err=%lu\r\n", GetLastError());
		return false;
	}

	LARGE_INTEGER li{};
	GetFileSizeEx(hFile, &li);
	size_t fileSize = static_cast<size_t>(li.QuadPart);

	std::vector<char> raw(fileSize + 1, 0);
	DWORD bytesRead = 0;
	ReadFile(hFile, raw.data(), static_cast<DWORD>(fileSize), &bytesRead, nullptr);
	CloseHandle(hFile);

	// Skip UTF-8 BOM if present
	const char* start = raw.data();
	if (fileSize >= 3 && (BYTE)start[0] == 0xEF && (BYTE)start[1] == 0xBB && (BYTE)start[2] == 0xBF) {
		start += 3;
	}

	// Convert to wide string
	int wideLen = MultiByteToWideChar(CP_UTF8, 0, start, -1, nullptr, 0);
	if (wideLen <= 0) {
		wprintf(L"[Error] Failed to convert config.ini to Unicode\r\n");
		return false;
	}
	std::vector<wchar_t> wideBuf(wideLen);
	MultiByteToWideChar(CP_UTF8, 0, start, -1, wideBuf.data(), wideLen);
	std::wstring content(wideBuf.data());

	// Parse line by line
	bool inAppSection = false;
	bool foundExe = false;
	bool foundMoniker = false;

	size_t pos = 0;
	while (pos < content.size()) {
		size_t eol = content.find_first_of(L"\r\n", pos);
		std::wstring line;
		if (eol == std::wstring::npos) {
			line = content.substr(pos);
			pos = content.size();
		}
		else {
			line = content.substr(pos, eol - pos);
			pos = eol + 1;
			if (pos < content.size() && content[pos - 1] == L'\r' && content[pos] == L'\n') ++pos;
		}

		// Trim and skip empty/comment lines
		std::wstring trimmed = TrimCopy(line);
		if (trimmed.empty() || trimmed[0] == L';' || trimmed[0] == L'#') continue;

		// Section header
		if (trimmed.front() == L'[' && trimmed.back() == L']') {
			std::wstring section = TrimCopy(trimmed.substr(1, trimmed.size() - 2));
			inAppSection = IEquals(section, L"App");
			LogDebug(L"[Config] Section: [%ls] (active=%ls)", section.c_str(), inAppSection ? L"yes" : L"no");
			continue;
		}

		if (!inAppSection) continue;

		// Key=Value
		size_t eq = trimmed.find(L'=');
		if (eq == std::wstring::npos) continue;

		std::wstring key = TrimCopy(trimmed.substr(0, eq));
		std::wstring val = TrimCopy(trimmed.substr(eq + 1));

		LogDebug(L"[Config] %ls = %ls", key.c_str(), val.c_str());

		if (IEquals(key, L"exe")) {
			if (!val.empty()) {
				g_CmdLineBuf.assign(val.begin(), val.end());
				g_CmdLineBuf.push_back(L'\0');
				ExeToLaunch = g_CmdLineBuf.data();
				foundExe = true;
				LogInfo(L"[Config] exe = %ls", ExeToLaunch);
			}
		}
		else if (IEquals(key, L"moniker")) {
			PackageMoniker = val;
			foundMoniker = true;
			LogInfo(L"[Config] moniker = %ls", PackageMoniker.c_str());
		}
		else if (IEquals(key, L"displayName")) {
			PackageDisplayName = val;
		}
		else if (IEquals(key, L"capabilities")) {
			if (!val.empty()) ParseCapabilityListFromArg(val.c_str());
		}
		else if (IEquals(key, L"allowPaths")) {
			if (!val.empty()) ParseAllowedPathListFromArg(val.c_str());
		}
		else if (IEquals(key, L"env")) {
			if (!val.empty()) ParseEnvListFromArg(val.c_str());
		}
		else if (IEquals(key, L"pathPrepend")) {
			if (!val.empty()) ParsePathPrependListFromArg(val.c_str());
		}
		else if (IEquals(key, L"wait")) {
			WaitForExit = IsBoolTrue(val);
		}
		else if (IEquals(key, L"retainProfile")) {
			RetainProfile = IsBoolTrue(val);
		}
		else if (IEquals(key, L"lpac")) {
			LaunchAsLpac = IsBoolTrue(val);
		}
		else if (IEquals(key, L"noWin32k")) {
			NoWin32k = IsBoolTrue(val);
		}
		else if (IEquals(key, L"lowIntegrityOnPaths")) {
			PathLowIntegrity = IsBoolTrue(val);
		}
		else if (IEquals(key, L"cleanupSubdirs")) {
			CleanupAllowedSubdirs = IsBoolTrue(val);
		}
		else if (IEquals(key, L"log")) {
			g_LogEnabled = IsBoolTrue(val);
		}
		else if (IEquals(key, L"conpty")) {
			UseConPty = IsBoolTrue(val);
		}
		else {
			LogWarn(L"[Config] Unknown key: %ls", key.c_str());
		}
	}

	if (!foundExe || !ExeToLaunch || wcslen(ExeToLaunch) == 0) {
		wprintf(L"[Error] config.ini: 'exe' is required in [App] section.\r\n");
		return false;
	}
	if (!foundMoniker || PackageMoniker.empty()) {
		wprintf(L"[Error] config.ini: 'moniker' is required in [App] section.\r\n");
		return false;
	}

	LogInfo(L"[Config] Loaded: exe='%ls', moniker='%ls', caps=%llu, paths=%llu, env=%llu",
		ExeToLaunch, PackageMoniker.c_str(),
		(unsigned long long)CapabilityList.size(),
		(unsigned long long)AllowedPaths.size(),
		(unsigned long long)EnvOverrides.size());
	return true;
}

// ========================================================================
// Environment Block Building
// ========================================================================
static void BuildChildEnvironmentBlock() {
	LogInfo(L"[Env] Building child environment block...");

	// Get parent environment
	LPWCH parentEnv = GetEnvironmentStringsW();
	if (!parentEnv) {
		LogError(L"[Env] GetEnvironmentStringsW failed.");
		return;
	}

	// Parse parent env into a map (case-insensitive key order)
	struct WstrCmpI {
		bool operator()(const std::wstring& a, const std::wstring& b) const {
			return _wcsicmp(a.c_str(), b.c_str()) < 0;
		}
	};
	std::vector<std::pair<std::wstring, std::wstring>> envPairs;

	// First pass: collect parent env
	const wchar_t* p = parentEnv;
	while (*p) {
		std::wstring entry(p);
		p += entry.size() + 1;

		// Skip entries starting with '=' (hidden env vars like =C:)
		if (!entry.empty() && entry[0] == L'=') {
			// Still include drive-letter vars
			envPairs.push_back({ entry.substr(0, entry.find(L'=', 1)), entry.substr(entry.find(L'=', 1) + 1) });
			continue;
		}

		size_t eq = entry.find(L'=');
		if (eq == std::wstring::npos) continue;
		envPairs.push_back({ entry.substr(0, eq), entry.substr(eq + 1) });
	}
	FreeEnvironmentStringsW(parentEnv);

	// Apply overrides
	for (const auto& ov : EnvOverrides) {
		bool found = false;
		for (auto& ep : envPairs) {
			if (IEquals(ep.first, ov.name)) {
				LogDebug(L"[Env] Override: %ls = %ls (was: %ls)", ov.name.c_str(), ov.value.c_str(), ep.second.c_str());
				ep.second = ov.value;
				found = true;
				break;
			}
		}
		if (!found) {
			LogDebug(L"[Env] New var: %ls = %ls", ov.name.c_str(), ov.value.c_str());
			envPairs.push_back({ ov.name, ov.value });
		}
	}

	// Prepend to PATH
	if (!PathPrependEntries.empty()) {
		std::wstring prependStr;
		for (const auto& pp : PathPrependEntries) {
			if (!prependStr.empty()) prependStr += L';';
			prependStr += pp;
		}

		bool foundPath = false;
		for (auto& ep : envPairs) {
			if (IEquals(ep.first, L"PATH")) {
				LogDebug(L"[Env] PATH prepend: %ls", prependStr.c_str());
				ep.second = prependStr + L';' + ep.second;
				foundPath = true;
				break;
			}
		}
		if (!foundPath) {
			envPairs.push_back({ L"PATH", prependStr });
		}
	}

	// Build double-null-terminated block
	g_ChildEnv.clear();
	for (const auto& ep : envPairs) {
		std::wstring entry = ep.first + L'=' + ep.second;
		g_ChildEnv.insert(g_ChildEnv.end(), entry.begin(), entry.end());
		g_ChildEnv.push_back(L'\0');
	}
	g_ChildEnv.push_back(L'\0'); // double null terminator

	LogInfo(L"[Env] Environment block built: %llu entries, %llu wchars",
		(unsigned long long)envPairs.size(), (unsigned long long)g_ChildEnv.size());
}

// ========================================================================
// Console Control Handler
// ========================================================================
static HANDLE g_ChildProcess = nullptr;

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
	LogWarn(L"[Ctrl] Console control event: %lu", ctrlType);
	RestoreSavedSecurityOnce();
	CleanupBunVirtualDrive();
	return FALSE; // Let default handler proceed
}

// ========================================================================
// Process Launch in AppContainer
// ========================================================================
static int LaunchInAppContainer(PSID appContainerSid) {
	LogInfo(L"[Launch] Preparing to launch: %ls", ExeToLaunch);

	// Build SECURITY_CAPABILITIES
	SECURITY_CAPABILITIES secCaps{};
	secCaps.AppContainerSid = appContainerSid;
	secCaps.Capabilities = CapabilityList.empty() ? nullptr : CapabilityList.data();
	secCaps.CapabilityCount = static_cast<DWORD>(CapabilityList.size());

	// Determine if we should use ConPTY
	bool useConPty = false;
	if (UseConPty && WaitForExit) {
		if (InitConPtyApi()) {
			useConPty = true;
			LogInfo(L"[Launch] ConPTY mode enabled.");
		}
		else {
			LogWarn(L"[Launch] ConPTY requested but not available. Falling back to new console.");
		}
	}
	// Note: ConPTY auto-enable for TUI removed — AppContainer blocks SetConsoleMode
	// on pseudo-console handles, causing child TUI apps to fail with setRawMode errno=1.
	// Use CREATE_NEW_CONSOLE instead (conpty=false).

	// ConPTY handles and pipes
	void* hPC = nullptr;
	HANDLE hPipeInRead = nullptr, hPipeInWrite = nullptr;
	HANDLE hPipeOutRead = nullptr, hPipeOutWrite = nullptr;
	HANDLE hInputThread = nullptr, hOutputThread = nullptr;
	InputRelayCtx inputCtx{};
	HANDLE hStopEvent = nullptr;

	if (useConPty) {
		// Enable VT processing on parent console
		HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
		DWORD outMode = 0, inMode = 0;

		if (GetConsoleMode(hStdOut, &outMode)) {
			SetConsoleMode(hStdOut, outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);
		}
		if (GetConsoleMode(hStdIn, &inMode)) {
			// Raw mode: disable line input, echo, and processed input for TUI passthrough
			DWORD newInMode = inMode;
			newInMode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
			newInMode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
			SetConsoleMode(hStdIn, newInMode);
		}

		// Create pipes for ConPTY
		if (!CreatePipe(&hPipeInRead, &hPipeInWrite, nullptr, 0) ||
			!CreatePipe(&hPipeOutRead, &hPipeOutWrite, nullptr, 0)) {
			LogError(L"[Launch] CreatePipe failed: err=%lu", GetLastError());
			return 1;
		}

		COORD consoleSize = GetCurrentConsoleSize();
		HRESULT hr = g_pfnCreatePC(consoleSize, hPipeInRead, hPipeOutWrite, 0, &hPC);
		if (FAILED(hr)) {
			LogError(L"[Launch] CreatePseudoConsole failed: hr=0x%08lX", (DWORD)hr);
			CloseHandle(hPipeInRead); CloseHandle(hPipeInWrite);
			CloseHandle(hPipeOutRead); CloseHandle(hPipeOutWrite);
			return 1;
		}
		LogInfo(L"[Launch] PseudoConsole created: %dx%d", consoleSize.X, consoleSize.Y);
	}

	// Build attribute list
	// Need space for: SECURITY_CAPABILITIES + optionally PSEUDOCONSOLE
	DWORD attrCount = 1; // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
	if (useConPty) attrCount++;

	SIZE_T attrSize = 0;
	InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
	std::vector<BYTE> attrBuf(attrSize);
	LPPROC_THREAD_ATTRIBUTE_LIST attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());

	if (!InitializeProcThreadAttributeList(attrList, attrCount, 0, &attrSize)) {
		LogError(L"[Launch] InitializeProcThreadAttributeList failed: err=%lu", GetLastError());
		if (hPC) g_pfnClosePC(hPC);
		return 1;
	}

	if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
		&secCaps, sizeof(secCaps), nullptr, nullptr)) {
		LogError(L"[Launch] UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed: err=%lu", GetLastError());
		DeleteProcThreadAttributeList(attrList);
		if (hPC) g_pfnClosePC(hPC);
		return 1;
	}

	if (useConPty) {
		if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
			hPC, sizeof(hPC), nullptr, nullptr)) {
			LogError(L"[Launch] UpdateProcThreadAttribute(PSEUDOCONSOLE) failed: err=%lu", GetLastError());
			DeleteProcThreadAttributeList(attrList);
			g_pfnClosePC(hPC);
			return 1;
		}
	}

	// Prepare STARTUPINFOEX
	STARTUPINFOEXW si{};
	si.StartupInfo.cb = sizeof(si);
	si.lpAttributeList = attrList;

	// Saved console state for restore after child exits
	DWORD savedInMode = 0, savedOutMode = 0;
	UINT savedOutputCP = 0, savedInputCP = 0;
	bool consoleSaved = false;

	DWORD createFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
	if (useConPty) {
		// ConPTY: child gets pseudo-console, no separate window
	}
	else if (WaitForExit) {
		// Inherit parent's console: pre-configure for TUI, child renders in same window
		// This avoids Quick Edit Mode issues that plague CREATE_NEW_CONSOLE
		HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);

		// Save current console state
		if (GetConsoleMode(hStdIn, &savedInMode) && GetConsoleMode(hStdOut, &savedOutMode)) {
			consoleSaved = true;
			savedOutputCP = GetConsoleOutputCP();
			savedInputCP = GetConsoleCP();

			// Enable VT processing on output
			SetConsoleMode(hStdOut, savedOutMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);

			// Set raw input mode: disable line input, echo, processed input, quick edit
			DWORD rawIn = ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS;
			SetConsoleMode(hStdIn, rawIn);

			// UTF-8 for VT sequences
			SetConsoleOutputCP(CP_UTF8);
			SetConsoleCP(CP_UTF8);

			LogInfo(L"[Launch] Console pre-configured for TUI (inherited mode, Quick Edit disabled).");
		}

		// Suppress log output so it doesn't interfere with TUI
		g_SuppressConsoleLog = true;
		fflush(stdout);
	}
	else {
		// Not waiting: give child its own console
		createFlags |= CREATE_NEW_CONSOLE;
	}

	// Make a mutable copy of the command line
	std::vector<wchar_t> cmdBuf(ExeToLaunch, ExeToLaunch + wcslen(ExeToLaunch));
	cmdBuf.push_back(L'\0');

	// Use an allowed path as working directory (prefer opencode\work, fallback to first allowed path)
	std::wstring workDir;
	std::wstring exeDir = GetExeDir();
	std::wstring preferredWork = JoinPath(JoinPath(exeDir, L"opencode"), L"work");
	if (DirectoryExists(preferredWork) && VectorHasPathInsensitive(AllowedPaths, preferredWork)) {
		workDir = preferredWork;
	}
	else if (!AllowedPaths.empty()) {
		for (const auto& ap : AllowedPaths) {
			if (DirectoryExists(ap)) { workDir = ap; break; }
		}
	}
	LogInfo(L"[Launch] Working directory: %ls", workDir.empty() ? L"(inherit)" : workDir.c_str());

	PROCESS_INFORMATION pi{};
	LogInfo(L"[Launch] CreateProcessW: flags=0x%08lX, cmd='%ls'", createFlags, cmdBuf.data());

	BOOL ok = CreateProcessW(
		nullptr,
		cmdBuf.data(),
		nullptr, nullptr,
		FALSE,
		createFlags,
		g_ChildEnv.empty() ? nullptr : g_ChildEnv.data(),
		workDir.empty() ? nullptr : workDir.c_str(),
		&si.StartupInfo,
		&pi);

	DeleteProcThreadAttributeList(attrList);

	if (!ok) {
		DWORD err = GetLastError();
		// Restore console if we changed it
		if (consoleSaved) {
			HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
			HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleMode(hIn, savedInMode);
			SetConsoleMode(hOut, savedOutMode);
			SetConsoleOutputCP(savedOutputCP);
			SetConsoleCP(savedInputCP);
			g_SuppressConsoleLog = false;
		}
		LogError(L"[Launch] CreateProcessW failed: err=%lu", err);
		wprintf(L"[Error] CreateProcessW failed: %lu\r\n", err);
		if (hPC) g_pfnClosePC(hPC);
		if (hPipeInRead) CloseHandle(hPipeInRead);
		if (hPipeInWrite) CloseHandle(hPipeInWrite);
		if (hPipeOutRead) CloseHandle(hPipeOutRead);
		if (hPipeOutWrite) CloseHandle(hPipeOutWrite);
		return (int)err;
	}

	g_ChildProcess = pi.hProcess;
	LogInfo(L"[Launch] Process created: PID=%lu, TID=%lu", pi.dwProcessId, pi.dwThreadId);

	CloseHandle(pi.hThread);

	int exitCode = 0;

	if (WaitForExit) {
		if (useConPty) {
			// Close the write end of input pipe and read end of output pipe
			// (they belong to the child side now)
			CloseHandle(hPipeInRead); hPipeInRead = nullptr;
			CloseHandle(hPipeOutWrite); hPipeOutWrite = nullptr;

			// Suppress console logging so it doesn't interfere with TUI output
			g_SuppressConsoleLog = true;

			// Flush C runtime stdout buffer before relay takes over
			fflush(stdout);

			// Set console code page to UTF-8 for proper VT sequence handling
			SetConsoleOutputCP(CP_UTF8);
			SetConsoleCP(CP_UTF8);

			// Start relay threads
			hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			inputCtx.hPipeWrite = hPipeInWrite;
			inputCtx.hStopEvent = hStopEvent;

			hInputThread = CreateThread(nullptr, 0, ConPtyInputRelay, &inputCtx, 0, nullptr);
			hOutputThread = CreateThread(nullptr, 0, ConPtyOutputRelay, hPipeOutRead, 0, nullptr);

			LogInfo(L"[Launch] ConPTY relay threads started. Waiting for child exit...");
		}
		else {
			LogInfo(L"[Launch] Waiting for child exit (console inherited)...");
		}

		WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD code = 0;
		GetExitCodeProcess(pi.hProcess, &code);
		exitCode = static_cast<int>(code);
		LogInfo(L"[Launch] Child exited with code: %d", exitCode);

		if (useConPty) {
			// Signal input relay to stop
			if (hStopEvent) SetEvent(hStopEvent);

			// Close pseudo console (this will cause output relay to finish)
			if (hPC) { g_pfnClosePC(hPC); hPC = nullptr; }

			// Wait for relay threads
			if (hOutputThread) { WaitForSingleObject(hOutputThread, 5000); CloseHandle(hOutputThread); }
			if (hInputThread) { WaitForSingleObject(hInputThread, 1000); CloseHandle(hInputThread); }
			if (hStopEvent) CloseHandle(hStopEvent);
			if (hPipeInWrite) CloseHandle(hPipeInWrite);
			if (hPipeOutRead) CloseHandle(hPipeOutRead);
		}
	}
	else {
		LogInfo(L"[Launch] Not waiting for child (wait=false).");
		if (useConPty && hPC) {
			// Can't use ConPTY without waiting - close it
			g_pfnClosePC(hPC);
			if (hPipeInRead) CloseHandle(hPipeInRead);
			if (hPipeInWrite) CloseHandle(hPipeInWrite);
			if (hPipeOutRead) CloseHandle(hPipeOutRead);
			if (hPipeOutWrite) CloseHandle(hPipeOutWrite);
		}
	}

	// Restore console state if we modified it
	if (consoleSaved) {
		HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleMode(hIn, savedInMode);
		SetConsoleMode(hOut, savedOutMode);
		SetConsoleOutputCP(savedOutputCP);
		SetConsoleCP(savedInputCP);
		g_SuppressConsoleLog = false;
		LogInfo(L"[Launch] Console state restored.");
	}

	CloseHandle(pi.hProcess);
	g_ChildProcess = nullptr;
	return exitCode;
}

// ========================================================================
// Admin Elevation
// ========================================================================
static bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = nullptr;
	SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
		CheckTokenMembership(nullptr, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}
	return isAdmin != FALSE;
}

static int RelaunchAsAdmin(int argc, WCHAR** argv) {
	// Build the full command line for the elevated process
	wchar_t exePath[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exePath, MAX_PATH);

	std::wstring args;
	for (int i = 1; i < argc; i++) {
		if (!args.empty()) args += L' ';
		// Quote arguments that contain spaces
		std::wstring arg(argv[i]);
		if (arg.find(L' ') != std::wstring::npos) {
			args += L'"';
			args += arg;
			args += L'"';
		}
		else {
			args += arg;
		}
	}

	wprintf(L"[Info] Requesting administrator privileges...\r\n");

	SHELLEXECUTEINFOW sei = {};
	sei.cbSize = sizeof(sei);
	sei.lpVerb = L"runas";
	sei.lpFile = exePath;
	sei.lpParameters = args.empty() ? nullptr : args.c_str();
	sei.nShow = SW_SHOWNORMAL;
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;

	if (!ShellExecuteExW(&sei)) {
		DWORD err = GetLastError();
		if (err == ERROR_CANCELLED) {
			wprintf(L"[Error] Administrator privileges denied by user.\r\n");
		}
		else {
			wprintf(L"[Error] Failed to elevate: err=%lu\r\n", err);
		}
		return 1;
	}

	// Wait for the elevated process to finish and relay its exit code
	if (sei.hProcess) {
		WaitForSingleObject(sei.hProcess, INFINITE);
		DWORD exitCode = 0;
		GetExitCodeProcess(sei.hProcess, &exitCode);
		CloseHandle(sei.hProcess);
		return (int)exitCode;
	}
	return 0;
}

// ========================================================================
// Entry Point
// ========================================================================
int wmain(int argc, WCHAR** argv) {
	// Step 1: Parse config - CLI args or config.ini
	bool configOk = false;
	if (argc <= 1) {
		// No CLI args: try config.ini
		// Note: log may not be enabled yet, so LoadConfigFromIni prints to console
		configOk = LoadConfigFromIni();
	}
	else {
		configOk = ParseArguments(argc, argv);
	}

	// Initialize logging (now that g_LogEnabled may have been set)
	InitLogFile();

	if (!configOk) {
		if (argc <= 1) {
			wprintf(L"\r\nNo CLI arguments and config.ini load failed.\r\n\r\n");
		}
		PrintUsage();
		CloseLogFile();
		return 1;
	}

	if (!ExeToLaunch || wcslen(ExeToLaunch) == 0) {
		wprintf(L"[Error] No executable specified (-i or exe= in config.ini).\r\n");
		PrintUsage();
		CloseLogFile();
		return 1;
	}
	if (PackageMoniker.empty()) {
		wprintf(L"[Error] No moniker specified (-m or moniker= in config.ini).\r\n");
		PrintUsage();
		CloseLogFile();
		return 1;
	}

	LogInfo(L"========================================");
	LogInfo(L"LaunchAppContainer starting");
	LogInfo(L"  exe: %ls", ExeToLaunch);
	LogInfo(L"  moniker: %ls", PackageMoniker.c_str());
	LogInfo(L"  wait=%d, conpty=%d, lpac=%d, noWin32k=%d",
		WaitForExit ? 1 : 0, UseConPty ? 1 : 0, LaunchAsLpac ? 1 : 0, NoWin32k ? 1 : 0);
	LogInfo(L"========================================");

	// Step 2: Auto-detect TUI and adjust settings
	AutoEnableWaitForTuiIfNeeded();

	// Step 3: Apply default OpenCode environment paths
	ApplyDefaultOpenCodeEnvPaths();

	// Step 4: Bun runtime compatibility
	ApplyBunOpenTuiCompatibility();

	// Step 5: Resolve SUBST drives in exe path
	ResolveExePathIfSubst();

	// Step 5b: Auto-add exe's parent directory to allowed paths
	{
		std::wstring imagePath = ParseImagePathFromCommandLine(ExeToLaunch);
		if (!imagePath.empty()) {
			std::wstring exeParent = GetParentDir(imagePath);
			if (!exeParent.empty() && AddAllowedPathUnique(exeParent)) {
				LogInfo(L"[Auto] Added exe parent dir to allowed paths: %ls", exeParent.c_str());
			}
		}
	}

	// Step 6: Set up Bun virtual drive if needed
	SetupBunVirtualDrive();

	// Step 7: Create AppContainer profile
	PSID appContainerSid = nullptr;
	DWORD profileErr = CreateAppContainerProfileWithMoniker(&appContainerSid);
	if (profileErr != ERROR_SUCCESS) {
		wprintf(L"[Error] Failed to create AppContainer profile: %lu\r\n", profileErr);
		CleanupBunVirtualDrive();
		CloseLogFile();
		return (int)profileErr;
	}

	// Step 8: Grant access to allowed paths
	GrantAccessToAllowedPaths(appContainerSid);

	// Step 9: Build child environment block
	BuildChildEnvironmentBlock();

	// Step 10: Install console control handler
	SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

	// Step 11: Launch the process
	int exitCode = LaunchInAppContainer(appContainerSid);

	// Step 12: Cleanup
	LogInfo(L"[Cleanup] Starting cleanup sequence...");

	// Restore ACLs
	RestoreSavedSecurityOnce();

	// Cleanup Bun virtual drive
	CleanupBunVirtualDrive();

	// Cleanup allowed path subdirectories if requested
	if (CleanupAllowedSubdirs) {
		CleanupAllowedPathSubdirs();
	}

	// Delete AppContainer profile unless retained
	if (!RetainProfile) {
		DeleteAppContainerProfileWithMoniker();
	}

	// Free AppContainer SID
	if (appContainerSid) {
		FreeSid(appContainerSid);
	}

	SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);

	LogInfo(L"[Done] Exit code: %d", exitCode);
	CloseLogFile();
	return exitCode;
}