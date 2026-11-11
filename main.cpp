#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cwctype>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

static const wchar_t* DEFAULT_LIST =
    L"https://raw.githubusercontent.com/1Mets/Forensics/refs/heads/main/Tools.txt";

struct Item {
    std::wstring url;
    std::wstring dir;
    std::wstring file;
};

static HINTERNET g_session = nullptr;
static std::mutex g_print;
static std::atomic<unsigned long long> g_bytes{0};
static std::atomic<size_t> g_next{0}, g_ok{0}, g_fail{0};

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring Trim(const std::wstring& s) {
    size_t a = 0, b = s.size();
    while (a < b && (iswspace(s[a]) || s[a] == 0xFEFF)) a++;
    while (b > a && iswspace(s[b - 1])) b--;
    return s.substr(a, b - a);
}

static bool IStartsWith(const std::wstring& s, const std::wstring& p) {
    return s.size() >= p.size() &&
           _wcsnicmp(s.c_str(), p.c_str(), p.size()) == 0;
}

static void Log(const wchar_t* fmt, ...) {
    std::lock_guard<std::mutex> lk(g_print);
    va_list ap;
    va_start(ap, fmt);
    vwprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static bool HttpGet(const std::wstring& url,
                    const std::function<bool(const BYTE*, DWORD)>& sink,
                    std::wstring& err) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = uc.dwHostNameLength = uc.dwUrlPathLength =
        uc.dwExtraInfoLength = (DWORD)-1;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) {
        err = L"bad URL";
        return false;
    }
    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength) path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET con = WinHttpConnect(g_session, host.c_str(), uc.nPort, 0);
    if (!con) { err = L"connect failed"; return false; }

    HINTERNET req = WinHttpOpenRequest(con, L"GET", path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       secure ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        WinHttpCloseHandle(con);
        err = L"request failed";
        return false;
    }

    bool ok = false;
    do {
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(req, nullptr)) {
            err = L"network error " + std::to_wstring(GetLastError());
            break;
        }
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(req,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                            WINHTTP_NO_HEADER_INDEX);
        if (status != 200) {
            err = L"HTTP " + std::to_wstring(status);
            break;
        }
        std::vector<BYTE> buf(256 * 1024);
        ok = true;
        for (;;) {
            DWORD got = 0;
            if (!WinHttpReadData(req, buf.data(), (DWORD)buf.size(), &got)) {
                err = L"read error " + std::to_wstring(GetLastError());
                ok = false;
                break;
            }
            if (got == 0) break;
            if (!sink(buf.data(), got)) {
                err = L"write error";
                ok = false;
                break;
            }
        }
    } while (false);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    return ok;
}

static std::wstring FileNameFromUrl(const std::wstring& url) {
    std::wstring u = url;
    size_t q = u.find_first_of(L"?#");
    if (q != std::wstring::npos) u.resize(q);
    size_t slash = u.find_last_of(L'/');
    std::wstring name = (slash == std::wstring::npos) ? u : u.substr(slash + 1);
    for (auto& c : name)
        if (wcschr(L"<>:\"/\\|?*", c)) c = L'_';
    if (name.empty()) name = L"download.bin";
    return name;
}

static std::wstring ItemName(const Item& it) {
    return it.file.empty() ? FileNameFromUrl(it.url) : it.file;
}

static std::wstring CreateFreshRoot() {
    for (unsigned long long i = 1;; ++i) {
        std::wstring root = L"C:\\ss" + std::to_wstring(i);
        if (CreateDirectoryW(root.c_str(), nullptr)) return root;
        if (GetLastError() != ERROR_ALREADY_EXISTS && i > 1000) {
            fwprintf(stderr, L"Cannot create %s (error %lu)\n", root.c_str(),
                     GetLastError());
            exit(1);
        }
    }
}

static std::vector<Item> ParseList(const std::string& text,
                                   const std::wstring& root) {
    std::vector<Item> items;
    std::wstring all = Utf8ToWide(text);
    size_t pos = 0;
    while (pos <= all.size()) {
        size_t nl = all.find(L'\n', pos);
        std::wstring line =
            Trim(all.substr(pos, nl == std::wstring::npos ? nl : nl - pos));
        pos = (nl == std::wstring::npos) ? all.size() + 1 : nl + 1;
        if (line.empty() || line[0] == L'#') continue;

        std::wstring url, dir;
        size_t sep = line.find(L" - \"");
        if (sep != std::wstring::npos) {
            url = Trim(line.substr(0, sep));
            size_t a = sep + 4;
            size_t b = line.find(L'"', a);
            dir = line.substr(a, b == std::wstring::npos ? b : b - a);
        } else {
            url = line;
        }
        if (!IStartsWith(url, L"http")) continue;

        std::wstring d = dir;
        std::replace(d.begin(), d.end(), L'/', L'\\');
        if (IStartsWith(d, L"C:\\SS1") &&
            (d.size() == 6 || d[6] == L'\\')) {
            d = root + d.substr(6);
        } else if (d.empty()) {
            d = root;
        } else if (d.size() < 2 || d[1] != L':') {
            d = root + L"\\" + d;
        }
        while (d.size() > 3 && d.back() == L'\\') d.pop_back();

        std::wstring file;
        size_t bs = d.find_last_of(L'\\');
        if (bs != std::wstring::npos && bs + 1 < d.size()) {
            std::wstring last = d.substr(bs + 1);
            size_t dot = last.find_last_of(L'.');
            std::wstring ext = (dot == std::wstring::npos)
                                   ? L"" : last.substr(dot + 1);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
            static const wchar_t* fileExts[] = {
                L"exe", L"dll", L"msi", L"bat", L"cmd", L"ps1", L"jar",
                L"py",  L"txt", L"7z",  L"rar", L"com", L"sys", L"reg"};
            bool isFile = _wcsicmp(last.c_str(), FileNameFromUrl(url).c_str()) == 0 &&
                          ext != L"zip";
            for (auto e : fileExts)
                if (ext == e) isFile = true;
            if (isFile) {
                file = last;
                d = d.substr(0, bs);
            }
        }
        items.push_back({url, d, file});
    }
    return items;
}

static bool DownloadItem(const Item& it, unsigned long long& total,
                         std::wstring& err) {
    SHCreateDirectoryExW(nullptr, it.dir.c_str(), nullptr);
    std::wstring final = it.dir + L"\\" + ItemName(it);
    std::wstring part = final + L".part";

    HANDLE h = CreateFileW(part.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = L"cannot create file";
        return false;
    }
    total = 0;
    bool ok = HttpGet(
        it.url,
        [&](const BYTE* d, DWORD n) {
            DWORD w = 0;
            if (!WriteFile(h, d, n, &w, nullptr) || w != n) return false;
            total += n;
            g_bytes += n;
            return true;
        },
        err);
    CloseHandle(h);

    if (!ok) {
        g_bytes -= total;
        DeleteFileW(part.c_str());
        return false;
    }
    if (!MoveFileExW(part.c_str(), final.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        err = L"rename failed";
        return false;
    }
    return true;
}

static bool IsDir(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::vector<std::wstring> ListDir(const std::wstring& dir) {
    std::vector<std::wstring> v;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return v;
    do {
        if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
            v.push_back(fd.cFileName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return v;
}

static void RemoveTree(const std::wstring& p) {
    DWORD pa = GetFileAttributesW(p.c_str());
    bool link = pa != INVALID_FILE_ATTRIBUTES &&
                (pa & FILE_ATTRIBUTE_REPARSE_POINT);
    if (!link) {  
        for (auto& n : ListDir(p)) {
            std::wstring c = p + L"\\" + n;
            DWORD a = GetFileAttributesW(c.c_str());
            bool isDir = a != INVALID_FILE_ATTRIBUTES &&
                         (a & FILE_ATTRIBUTE_DIRECTORY);
            if (isDir) RemoveTree(c);
            else {
                SetFileAttributesW(c.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(c.c_str());
            }
        }
    }
    SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(p.c_str());
}

static void MergeMove(const std::wstring& src, const std::wstring& dst) {
    CreateDirectoryW(dst.c_str(), nullptr);
    for (auto& n : ListDir(src)) {
        std::wstring s = src + L"\\" + n, d = dst + L"\\" + n;
        if (IsDir(s)) {
            if (IsDir(d) || !MoveFileExW(s.c_str(), d.c_str(), 0))
                MergeMove(s, d);
        } else {
            MoveFileExW(s.c_str(), d.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
        }
    }
}

static bool RunHidden(std::wstring cmd) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static bool ExtractZip(const std::wstring& zip, const std::wstring& dir,
                       std::wstring& err) {
    std::wstring tmp = zip + L".extract";
    RemoveTree(tmp);
    CreateDirectoryW(tmp.c_str(), nullptr);

    bool ok = RunHidden(L"tar.exe -xf \"" + zip + L"\" -C \"" + tmp + L"\"");
    if (!ok) {
        RemoveTree(tmp);
        CreateDirectoryW(tmp.c_str(), nullptr);
        ok = RunHidden(L"powershell.exe -NoProfile -Command \"Expand-Archive "
                       L"-LiteralPath '" + zip + L"' -DestinationPath '" +
                       tmp + L"' -Force\"");
    }
    if (!ok) {
        RemoveTree(tmp);
        err = L"extract failed (zip kept)";
        return false;
    }

    std::wstring root = tmp;
    for (;;) {
        auto e = ListDir(root);
        if (e.size() == 1 && IsDir(root + L"\\" + e[0])) root += L"\\" + e[0];
        else break;
    }
    MergeMove(root, dir);
    RemoveTree(tmp);
    DeleteFileW(zip.c_str());
    return true;
}

static void Worker(const std::vector<Item>& items) {
    for (;;) {
        size_t i = g_next++;
        if (i >= items.size()) return;
        const Item& it = items[i];

        std::wstring err;
        unsigned long long sz = 0;
        bool ok = false;
        for (int attempt = 1; attempt <= 3 && !ok; ++attempt) {
            ok = DownloadItem(it, sz, err);
            if (!ok) Sleep(500 * attempt);
        }
        std::wstring name = ItemName(it);
        bool isZip = name.size() > 4 &&
                     _wcsicmp(name.c_str() + name.size() - 4, L".zip") == 0;
        if (ok && isZip) {
            std::wstring zerr;
            if (ExtractZip(it.dir + L"\\" + name, it.dir, zerr)) {
                g_ok++;
                Log(L"[%3zu/%zu] OK    %-40s %7.2f MB (extracted)\n", i + 1,
                    items.size(), name.c_str(), sz / 1048576.0);
            } else {
                g_fail++;
                Log(L"[%3zu/%zu] FAIL  %-40s %s\n", i + 1, items.size(),
                    name.c_str(), zerr.c_str());
            }
        } else if (ok) {
            g_ok++;
            Log(L"[%3zu/%zu] OK    %-40s %7.2f MB\n", i + 1, items.size(),
                name.c_str(), sz / 1048576.0);
        } else {
            g_fail++;
            Log(L"[%3zu/%zu] FAIL  %-40s %s\n", i + 1, items.size(),
                name.c_str(), err.c_str());
        }
    }
}

static bool PathUnder(const std::wstring& path, const std::wstring& root) {
    return path.size() > root.size() &&
           _wcsnicmp(path.c_str(), root.c_str(), root.size()) == 0 &&
           path[root.size()] == L'\\';
}

static int KillProcessesIn(const std::wstring& root) {
    int killed = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD self = GetCurrentProcessId();
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == self) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                       PROCESS_TERMINATE | SYNCHRONIZE,
                                   FALSE, pe.th32ProcessID);
            if (!h) continue;
            std::vector<wchar_t> buf(32768);
            DWORD n = (DWORD)buf.size();
            if (QueryFullProcessImageNameW(h, 0, buf.data(), &n) &&
                PathUnder(std::wstring(buf.data(), n), root)) {
                if (TerminateProcess(h, 1)) {
                    WaitForSingleObject(h, 3000);
                    killed++;
                    wprintf(L"  killed %s (PID %lu)\n", pe.szExeFile,
                            pe.th32ProcessID);
                } else {
                    wprintf(L"  could not kill %s (PID %lu, error %lu)\n",
                            pe.szExeFile, pe.th32ProcessID, GetLastError());
                }
            }
            CloseHandle(h);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return killed;
}

static int Cleanup(unsigned long long only) {
    std::vector<std::wstring> roots;
    if (only) {
        std::wstring r = L"C:\\ss" + std::to_wstring(only);
        if (IsDir(r)) roots.push_back(r);
    } else {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(L"C:\\ss*", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                std::wstring n = fd.cFileName;
                bool digits = n.size() > 2;
                for (size_t i = 2; i < n.size(); ++i)
                    if (!iswdigit(n[i])) digits = false;
                if (digits && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    roots.push_back(L"C:\\" + n);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    if (roots.empty()) {
        wprintf(L"No ss folders found.\n");
        return 0;
    }

    int failed = 0;
    for (auto& root : roots) {
        wprintf(L"Cleaning %s\n", root.c_str());
        for (int pass = 0; pass < 3; ++pass)
            if (KillProcessesIn(root) == 0) break;

        for (int attempt = 0; attempt < 6 && IsDir(root); ++attempt) {
            RemoveTree(root);
            if (IsDir(root)) {
                Sleep(500);
                KillProcessesIn(root);
            }
        }
        if (IsDir(root)) {
            wprintf(L"  FAILED to fully delete %s (files in use? try as admin)\n",
                    root.c_str());
            failed++;
        } else {
            wprintf(L"  deleted %s\n", root.c_str());
        }
    }
    return failed ? 2 : 0;
}

int wmain(int argc, wchar_t** argv) {
    std::wstring listUrl = DEFAULT_LIST;
    unsigned threads = 16;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"-j" && i + 1 < argc) threads = std::max(1, _wtoi(argv[++i]));
        else if (a == L"-u" && i + 1 < argc) listUrl = argv[++i];
        else if (a == L"-cleanup") {
            unsigned long long n = 0;
            if (i + 1 < argc && iswdigit(argv[i + 1][0]))
                n = _wcstoui64(argv[++i], nullptr, 10);
            return Cleanup(n);
        }
        else {
            wprintf(L"Usage: fastdl [-j threads] [-u list_url]\n"
                    L"       fastdl -cleanup [N]\n");
            return 1;
        }
    }

    g_session = WinHttpOpen(L"fastdl/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) {
        fwprintf(stderr, L"WinHttpOpen failed\n");
        return 1;
    }
    DWORD maxConns = 32;
    WinHttpSetOption(g_session, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &maxConns,
                     sizeof(maxConns));
#ifdef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
    DWORD protos = WINHTTP_PROTOCOL_FLAG_HTTP2;
    WinHttpSetOption(g_session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &protos,
                     sizeof(protos));
#endif
#ifdef WINHTTP_OPTION_DECOMPRESSION
    DWORD decomp = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(g_session, WINHTTP_OPTION_DECOMPRESSION, &decomp,
                     sizeof(decomp));
#endif

    wprintf(L"Fetching list...\n");
    std::string listText;
    std::wstring err;
    if (!HttpGet(listUrl,
                 [&](const BYTE* d, DWORD n) {
                     listText.append((const char*)d, n);
                     return true;
                 },
                 err)) {
        fwprintf(stderr, L"Could not fetch list: %s\n", err.c_str());
        return 1;
    }

    std::wstring root = CreateFreshRoot();
    std::vector<Item> items = ParseList(listText, root);
    if (items.empty()) {
        wprintf(L"No valid entries found in list.\n");
        return 1;
    }
    threads = std::min<unsigned>(threads, (unsigned)items.size());
    wprintf(L"Output root : %s\nFiles       : %zu\nThreads     : %u\n\n",
            root.c_str(), items.size(), threads);

    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> pool;
    for (unsigned i = 0; i < threads; ++i)
        pool.emplace_back(Worker, std::cref(items));
    for (auto& t : pool) t.join();
    double secs = std::chrono::duration<double>(
                      std::chrono::steady_clock::now() - t0).count();

    double mb = g_bytes.load() / 1048576.0;
    wprintf(L"\nDone: %zu ok, %zu failed | %.2f MB in %.1fs (%.2f MB/s)\n"
            L"Saved to %s\n",
            g_ok.load(), g_fail.load(), mb, secs, secs > 0 ? mb / secs : 0.0,
            root.c_str());

    WinHttpCloseHandle(g_session);
    return g_fail ? 2 : 0;
}
