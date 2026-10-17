/* gui_windows.c - desktop window for EraseCure on Windows.
 * SPDX-License-Identifier: MIT
 *
 * The window is a thin front end: each button runs this same .exe with
 * command-line arguments (exactly what you could type in PowerShell) and
 * streams its output into the panel. So the app and the CLI share one tested
 * code path, and a slow wipe never freezes the window. */
#include "erasecure.h"

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <string.h>
#include <wchar.h>

enum {
    ID_DEVICES = 101, ID_SHRED_FILE, ID_SHRED_DIR, ID_CARVE, ID_IMAGE,
    ID_WIPE_FILE, ID_WIPE_DRIVE, ID_AUDIT, ID_ADMIN, ID_CLEAR,
    ID_DRIVE, ID_OUT, ID_DRIVE_LABEL,
    WM_EC_TEXT = WM_APP + 1, WM_EC_DONE
};

static const struct { int id; const wchar_t *label; } buttons[] = {
    {ID_DEVICES, L"List drives"},
    {ID_SHRED_FILE, L"Shred a file\x2026"},
    {ID_SHRED_DIR, L"Shred a folder\x2026"},
    {ID_WIPE_FILE, L"Wipe a file/image\x2026"},
    {ID_IMAGE, L"Copy drive to image\x2026"},
    {ID_CARVE, L"Recover files from image\x2026"},
    {ID_WIPE_DRIVE, L"Wipe drive\x2026"},
    {ID_AUDIT, L"Check audit log"},
};
#define NBTN (int)(sizeof buttons / sizeof *buttons)

static HWND g_win, g_out, g_drive, g_label, g_btn[NBTN], g_admin, g_clear;
static HFONT g_ui, g_mono;
static int g_busy, g_dpi = 96;
static wchar_t g_self[MAX_PATH];

static int px(int v) { return MulDiv(v, g_dpi, 96); }

static int is_elevated(void)
{
    HANDLE tok;
    TOKEN_ELEVATION e = {0};
    DWORD n;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n);
    CloseHandle(tok);
    return e.TokenIsElevated != 0;
}

static void append(const wchar_t *s)
{
    int len = GetWindowTextLengthW(g_out);
    SendMessageW(g_out, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_out, EM_REPLACESEL, FALSE, (LPARAM)s);
}

static void set_busy(int busy)
{
    g_busy = busy;
    for (int i = 0; i < NBTN; i++) EnableWindow(g_btn[i], !busy);
    EnableWindow(g_admin, !busy && !is_elevated());
}

/* ---- running ourselves as a child process ---- */

/* Quote one argument per the CommandLineToArgvW rules. */
static void quote(wchar_t *cmd, size_t cap, const wchar_t *a)
{
    size_t n = wcslen(cmd);
    if (n + 2 >= cap) return;
    if (n) cmd[n++] = L' '; /* a leading space would shift every argument */
    cmd[n++] = L'"';
    for (const wchar_t *p = a; *p && n + 4 < cap; p++) {
        size_t bs = 0;
        while (p[bs] == L'\\') bs++;
        if (bs) {
            /* backslashes are literal unless they precede a quote or the end */
            int dbl = p[bs] == L'"' || p[bs] == 0;
            for (size_t i = 0; i < bs * (dbl ? 2 : 1) && n + 4 < cap; i++) cmd[n++] = L'\\';
            p += bs - 1;
            continue;
        }
        if (*p == L'"') cmd[n++] = L'\\';
        cmd[n++] = *p;
    }
    cmd[n++] = L'"';
    cmd[n] = 0;
}

typedef struct { HANDLE proc, pipe; } job;

static DWORD WINAPI reader(LPVOID arg)
{
    job *j = arg;
    char buf[4096], acc[8192];
    size_t used = 0;
    DWORD got;
    for (;;) {
        BOOL ok = ReadFile(j->pipe, buf, sizeof buf, &got, NULL);
        if (ok && got) {
            if (used + got > sizeof acc) used = 0; /* runaway line: drop */
            memcpy(acc + used, buf, got);
            used += got;
        }
        /* Hand over complete lines only, so UTF-8 is never split. */
        size_t cut = used;
        if (ok && got)
            while (cut && acc[cut - 1] != '\n') cut--;
        if (cut) {
            int wn = MultiByteToWideChar(CP_UTF8, 0, acc, (int)cut, NULL, 0);
            wchar_t *w = malloc(((size_t)wn * 2 + 1) * sizeof *w), *o = w;
            if (w) {
                wchar_t *tmp = malloc(((size_t)wn + 1) * sizeof *tmp);
                if (tmp) {
                    MultiByteToWideChar(CP_UTF8, 0, acc, (int)cut, tmp, wn);
                    for (int i = 0; i < wn; i++) { /* edit controls need CRLF */
                        if (tmp[i] == L'\n' && (i == 0 || tmp[i - 1] != L'\r')) *o++ = L'\r';
                        *o++ = tmp[i];
                    }
                    free(tmp);
                }
                *o = 0;
                PostMessageW(g_win, WM_EC_TEXT, 0, (LPARAM)w);
            }
            memmove(acc, acc + cut, used - cut);
            used -= cut;
        }
        if (!ok || !got) break;
    }
    DWORD code = 1;
    WaitForSingleObject(j->proc, INFINITE);
    GetExitCodeProcess(j->proc, &code);
    CloseHandle(j->proc);
    CloseHandle(j->pipe);
    free(j);
    PostMessageW(g_win, WM_EC_DONE, code, 0);
    return 0;
}

static void run(const wchar_t *title, const wchar_t *const *args, int n)
{
    wchar_t cmd[8192] = L"";
    quote(cmd, 8192, g_self);
    for (int i = 0; i < n; i++) quote(cmd, 8192, args[i]);

    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE rd, wr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si = {0};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi;
    wchar_t head[600];
    _snwprintf(head, 600, L"\r\n>>> %ls\r\n", title);
    head[599] = 0;
    append(head);
    if (!CreateProcessW(g_self, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        append(L"Could not start the operation.\r\n");
        CloseHandle(rd);
        CloseHandle(wr);
        return;
    }
    CloseHandle(wr);
    CloseHandle(pi.hThread);
    job *j = malloc(sizeof *j);
    if (!j) return;
    j->proc = pi.hProcess;
    j->pipe = rd;
    set_busy(1);
    HANDLE t = CreateThread(NULL, 0, reader, j, 0, NULL);
    if (t) CloseHandle(t);
}

/* ---- pickers and confirmations ---- */

static int pick_file(wchar_t *out, int save, const wchar_t *filter, const wchar_t *title)
{
    OPENFILENAMEW o = {0};
    o.lStructSize = sizeof o;
    out[0] = 0;
    o.hwndOwner = g_win;
    o.lpstrFile = out;
    o.nMaxFile = MAX_PATH * 4;
    o.lpstrFilter = filter;
    o.lpstrTitle = title;
    o.lpstrDefExt = save ? L"img" : NULL;
    o.Flags = OFN_NOCHANGEDIR | (save ? OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST
                                      : OFN_FILEMUSTEXIST);
    return save ? GetSaveFileNameW(&o) : GetOpenFileNameW(&o);
}

static int pick_folder(wchar_t *out, const wchar_t *title)
{
    BROWSEINFOW b = {0};
    b.hwndOwner = g_win;
    b.lpszTitle = title;
    b.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE id = SHBrowseForFolderW(&b);
    if (!id) return 0;
    int ok = SHGetPathFromIDListW(id, out);
    CoTaskMemFree(id);
    return ok;
}

static int confirm(const wchar_t *what)
{
    return MessageBoxW(g_win, what, L"EraseCure \x2013 confirm",
                       MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

static int read_drive(wchar_t *d)
{
    GetWindowTextW(g_drive, d, 64);
    if (_wcsnicmp(d, L"\\\\.\\PhysicalDrive", 17) || d[17] < L'0' || d[17] > L'9') {
        MessageBoxW(g_win, L"Type a drive like \\\\.\\PhysicalDrive2 in the Drive box first.\n"
                           L"Click \"List drives\" to see the names.",
                    L"EraseCure", MB_ICONINFORMATION);
        return 0;
    }
    return 1;
}

static void on_command(int id)
{
    wchar_t a[MAX_PATH * 4], b[MAX_PATH * 4], msg[MAX_PATH * 5], d[64];
    static const wchar_t any[] = L"All files\0*.*\0";
    static const wchar_t img[] = L"Disk images\0*.img;*.dd;*.raw;*.bin;*.iso\0All files\0*.*\0";

    switch (id) {
    case ID_DEVICES: {
        const wchar_t *v[] = {L"devices"};
        run(L"List drives", v, 1);
        break;
    }
    case ID_SHRED_FILE:
        if (!pick_file(a, 0, any, L"Choose a file to shred")) break;
        _snwprintf(msg, MAX_PATH * 5, L"Permanently erase this file? It cannot be recovered.\n\n%ls", a);
        if (confirm(msg)) {
            const wchar_t *v[] = {L"shred", a};
            run(L"Shred file", v, 2);
        }
        break;
    case ID_SHRED_DIR:
        if (!pick_folder(a, L"Choose a folder to shred (everything inside is erased)")) break;
        _snwprintf(msg, MAX_PATH * 5, L"Permanently erase this folder and EVERYTHING in it?\n\n%ls", a);
        if (confirm(msg)) {
            const wchar_t *v[] = {L"shred", a};
            run(L"Shred folder", v, 2);
        }
        break;
    case ID_WIPE_FILE:
        if (!pick_file(a, 0, img, L"Choose a file or disk image to overwrite")) break;
        _snwprintf(msg, MAX_PATH * 5, L"Overwrite the whole content of this file with zeros?\n\n%ls", a);
        if (confirm(msg)) {
            const wchar_t *v[] = {L"wipe", a};
            run(L"Wipe file", v, 2);
        }
        break;
    case ID_IMAGE:
        if (!read_drive(d) || !pick_file(a, 1, img, L"Save the drive copy as")) break;
        DeleteFileW(a); /* the save dialog already asked before replacing */
        {
            const wchar_t *v[] = {L"image", d, a};
            run(L"Copy drive to image (read-only)", v, 3);
        }
        break;
    case ID_CARVE:
        if (!pick_file(a, 0, img, L"Choose the disk image to recover from") ||
            !pick_folder(b, L"Choose where to save recovered files"))
            break;
        /* Keep results together instead of spilling them into the chosen folder. */
        wcsncat(b, L"\\EraseCure recovered files", MAX_PATH * 4 - wcslen(b) - 1);
        {
            const wchar_t *v[] = {L"carve", a, b};
            run(L"Recover files", v, 3);
        }
        break;
    case ID_WIPE_DRIVE:
        if (!read_drive(d)) break;
        _snwprintf(msg, MAX_PATH * 5,
                   L"EVERYTHING on %ls will be destroyed.\n\n"
                   L"Check the size and model in \"List drives\" first. "
                   L"EraseCure refuses drives that still have partitions; "
                   L"clear it first with Clear-Disk if you are sure.\n\nContinue?", d);
        if (confirm(msg)) {
            const wchar_t *v[] = {L"wipe", d, L"--confirm", d};
            run(L"Wipe drive", v, 4);
        }
        break;
    case ID_AUDIT: {
        const wchar_t *v[] = {L"audit-verify"};
        run(L"Check audit log", v, 1);
        break;
    }
    case ID_ADMIN:
        if ((INT_PTR)ShellExecuteW(NULL, L"runas", g_self, L"gui", NULL, SW_SHOWNORMAL) > 32)
            DestroyWindow(g_win);
        break;
    case ID_CLEAR:
        SetWindowTextW(g_out, L"");
        break;
    }
}

/* ---- window ---- */

static void layout(int w, int h)
{
    int m = px(10), bh = px(30), gap = px(6), cols = 4;
    int bw = (w - 2 * m - (cols - 1) * gap) / cols;
    for (int i = 0; i < NBTN; i++)
        MoveWindow(g_btn[i], m + (i % cols) * (bw + gap), m + (i / cols) * (bh + gap), bw, bh, TRUE);
    int y = m + 2 * (bh + gap) + px(4);
    MoveWindow(g_label, m, y + px(6), px(46), px(20), TRUE);
    MoveWindow(g_drive, m + px(50), y + px(2), px(240), px(26), TRUE);
    MoveWindow(g_admin, w - m - px(190), y, px(190), bh, TRUE);
    MoveWindow(g_clear, w - m - px(190) - gap - px(110), y, px(110), bh, TRUE);
    y += bh + gap;
    MoveWindow(g_out, m, y, w - 2 * m, h - y - m, TRUE);
}

static HWND child(const wchar_t *cls, const wchar_t *text, DWORD style, int id, HFONT f)
{
    HWND h = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g_win,
                             (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE);
    return h;
}

static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        g_win = h;
        for (int i = 0; i < NBTN; i++)
            g_btn[i] = child(L"BUTTON", buttons[i].label, BS_PUSHBUTTON | WS_TABSTOP,
                             buttons[i].id, g_ui);
        g_label = child(L"STATIC", L"Drive:", 0, ID_DRIVE_LABEL, g_ui);
        g_drive = child(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, ID_DRIVE, g_ui);
        SendMessageW(g_drive, EM_SETCUEBANNER, TRUE, (LPARAM)L"\\\\.\\PhysicalDrive2");
        g_clear = child(L"BUTTON", L"Clear output", BS_PUSHBUTTON, ID_CLEAR, g_ui);
        g_admin = child(L"BUTTON", L"Restart as Administrator", BS_PUSHBUTTON, ID_ADMIN, g_ui);
        g_out = child(L"EDIT", L"", WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY |
                                        ES_AUTOVSCROLL, ID_OUT, g_mono); /* wraps long lines */
        SendMessageW(g_out, EM_SETLIMITTEXT, 0, 0);
        EnableWindow(g_admin, !is_elevated());
        append(L"EraseCure " EC_VERSION L" \x2013 data sanitization and recovery\r\n"
               L"Files: Shred / Wipe.  Recovery: Copy drive to image, then Recover files.\r\n"
               L"Drive actions need \"Restart as Administrator\". Every action is logged to "
               L"erasecure-audit.jsonl next to this program.\r\n");
        on_command(ID_DEVICES);
        return 0;
    }
    case WM_SIZE:
        layout(LOWORD(lp), HIWORD(lp));
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)lp)->ptMinTrackSize.x = px(720);
        ((MINMAXINFO *)lp)->ptMinTrackSize.y = px(420);
        return 0;
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED && !g_busy) on_command(LOWORD(wp));
        return 0;
    case WM_EC_TEXT:
        append((wchar_t *)lp);
        free((void *)lp);
        return 0;
    case WM_EC_DONE:
        append(wp == 0 ? L"[OK] Done.\r\n" : L"[!] Finished with errors - see above.\r\n");
        set_busy(0);
        return 0;
    case WM_CLOSE:
        if (g_busy && MessageBoxW(h, L"An operation is still running. Quit anyway?", L"EraseCure",
                                  MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
            return 0;
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

int ec_gui_run(void)
{
    GetModuleFileNameW(NULL, g_self, MAX_PATH);
    /* Log next to the program, not wherever Explorer started us. */
    wchar_t dir[MAX_PATH];
    wcscpy(dir, g_self);
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (slash) { *slash = 0; SetCurrentDirectoryW(dir); }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    HDC dc = GetDC(NULL);
    g_dpi = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(NULL, dc);
    g_ui = CreateFontW(-px(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                       CLEARTYPE_QUALITY, 0, L"Segoe UI");
    g_mono = CreateFontW(-px(14), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                         CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"EraseCureWindow";
    RegisterClassW(&wc);
    wchar_t title[96];
    _snwprintf(title, 96, L"EraseCure %ls%ls", L"" EC_VERSION,
               is_elevated() ? L" (Administrator)" : L"");
    title[95] = 0;
    HWND w = CreateWindowExW(0, wc.lpszClassName, title, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                             CW_USEDEFAULT, px(980), px(640), NULL, NULL, wc.hInstance, NULL);
    if (!w) return 1;
    ShowWindow(w, SW_SHOWNORMAL);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (IsDialogMessageW(w, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}
