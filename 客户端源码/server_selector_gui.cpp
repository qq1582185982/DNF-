/*
 * 服务器选择GUI窗口实现
 */

#include "server_selector_gui.h"
#include <commctrl.h>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

ServerSelectorGUI::ServerSelectorGUI()
    : hwnd(NULL), hInstance(GetModuleHandle(NULL)),
      selected_index(-1), user_confirmed(false) {
}

ServerSelectorGUI::~ServerSelectorGUI() {
    if (hwnd) {
        DestroyWindow(hwnd);
    }
}

bool ServerSelectorGUI::ShowDialog(const std::vector<ServerInfo>& server_list,
                                   int last_server_id,
                                   ServerInfo& selected_server) {
    servers = server_list;
    selected_index = -1;
    user_confirmed = false;

    // 初始化窗口
    if (!InitWindow()) {
        return false;
    }

    // 填充服务器列表
    PopulateServerList(last_server_id);

    // 显示窗口
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        // 如果窗口已关闭，退出循环
        if (!IsWindow(hwnd)) {
            break;
        }
    }

    // 返回选择结果
    if (user_confirmed && selected_index >= 0 && selected_index < (int)servers.size()) {
        selected_server = servers[selected_index];
        return true;
    }

    return false;
}

bool ServerSelectorGUI::InitWindow() {
    // 注册窗口类
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"DNFServerSelector";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 40));  // 暗色背景，仿DNF风格

    RegisterClassW(&wc);

    // 创建窗口（居中显示）
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    int window_width = 450;
    int window_height = 550;
    int x = (screen_width - window_width) / 2;
    int y = (screen_height - window_height) / 2;

    hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,  // 模态对话框样式
        L"DNFServerSelector",
        L"选择服务器",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y, window_width, window_height,
        NULL, NULL, hInstance, this  // 传递this指针
    );

    if (!hwnd) {
        return false;
    }

    // 设置窗口数据（存储this指针）
    SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)this);

    // 创建控件
    // 1. 标题文本
    HWND hTitle = CreateWindowW(
        L"STATIC", L"请选择游戏服务器",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        20, 20, 410, 30,
        hwnd, NULL, hInstance, NULL
    );

    // 设置标题字体（加粗，大号）
    HFONT hTitleFont = CreateFont(
        22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // 2. 服务器列表（ListBox）
    HWND hList = CreateWindowW(
        L"LISTBOX", NULL,
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
        20, 70, 410, 300,
        hwnd, (HMENU)IDC_SERVER_LIST, hInstance, NULL
    );

    // 设置列表字体
    HFONT hListFont = CreateFont(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hList, WM_SETFONT, (WPARAM)hListFont, TRUE);

    // 3. 服务器详情显示
    HWND hInfo = CreateWindowW(
        L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, 385, 410, 50,
        hwnd, (HMENU)IDC_STATIC_INFO, hInstance, NULL
    );

    // 设置详情字体
    HFONT hInfoFont = CreateFont(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hInfo, WM_SETFONT, (WPARAM)hInfoFont, TRUE);

    // 4. 连接按钮
    HWND hBtnConnect = CreateWindowW(
        L"BUTTON", L"连接",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        90, 460, 120, 40,
        hwnd, (HMENU)IDC_BTN_CONNECT, hInstance, NULL
    );

    // 设置按钮字体
    HFONT hButtonFont = CreateFont(
        16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hBtnConnect, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    // 5. 取消按钮
    HWND hBtnCancel = CreateWindowW(
        L"BUTTON", L"取消",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        240, 460, 120, 40,
        hwnd, (HMENU)IDC_BTN_CANCEL, hInstance, NULL
    );
    SendMessage(hBtnCancel, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    return true;
}

void ServerSelectorGUI::PopulateServerList(int last_server_id) {
    HWND hList = GetDlgItem(hwnd, IDC_SERVER_LIST);

    // 清空列表
    SendMessage(hList, LB_RESETCONTENT, 0, 0);

    // 添加服务器到列表
    int default_index = -1;
    for (size_t i = 0; i < servers.size(); i++) {
        // 格式: "服务器名 (ID: 1)"
        std::wostringstream oss;
        oss << servers[i].name << L" (ID: " << servers[i].id << L")";
        std::wstring item_text = oss.str();

        SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)item_text.c_str());

        // 如果是上次选择的服务器，记录索引
        if (servers[i].id == last_server_id) {
            default_index = i;
        }
    }

    // 如果有上次选择，自动选中
    if (default_index >= 0) {
        SendMessage(hList, LB_SETCURSEL, default_index, 0);
        selected_index = default_index;
        UpdateServerInfo(default_index);
    }
}

void ServerSelectorGUI::UpdateServerInfo(int index) {
    if (index < 0 || index >= (int)servers.size()) {
        SetDlgItemTextW(hwnd, IDC_STATIC_INFO, L"");
        return;
    }

    const ServerInfo& info = servers[index];

    // 格式化服务器详情
    std::wostringstream oss;
    oss << L"游戏服务器: " << info.game_server_ip.c_str() << L"\r\n";
    oss << L"隧道服务器: " << info.tunnel_server_ip.c_str()
        << L":" << info.tunnel_port;

    SetDlgItemTextW(hwnd, IDC_STATIC_INFO, oss.str().c_str());
}

void ServerSelectorGUI::OnConnectClick() {
    HWND hList = GetDlgItem(hwnd, IDC_SERVER_LIST);
    int sel = SendMessage(hList, LB_GETCURSEL, 0, 0);

    if (sel == LB_ERR) {
        MessageBoxW(hwnd, L"请先选择一个服务器！", L"提示", MB_OK | MB_ICONWARNING);
        return;
    }

    selected_index = sel;
    user_confirmed = true;

    // 关闭窗口
    DestroyWindow(hwnd);
    PostQuitMessage(0);
}

void ServerSelectorGUI::OnCancelClick() {
    selected_index = -1;
    user_confirmed = false;

    // 关闭窗口
    DestroyWindow(hwnd);
    PostQuitMessage(0);
}

void ServerSelectorGUI::OnListSelectionChange() {
    HWND hList = GetDlgItem(hwnd, IDC_SERVER_LIST);
    int sel = SendMessage(hList, LB_GETCURSEL, 0, 0);

    if (sel != LB_ERR) {
        selected_index = sel;
        UpdateServerInfo(sel);
    }
}

LRESULT CALLBACK ServerSelectorGUI::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // 获取this指针
    ServerSelectorGUI* pThis = nullptr;

    if (msg == WM_CREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (ServerSelectorGUI*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (ServerSelectorGUI*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (msg) {
        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED) {
                int ctrl_id = LOWORD(wParam);
                if (ctrl_id == IDC_BTN_CONNECT) {
                    pThis->OnConnectClick();
                    return 0;
                } else if (ctrl_id == IDC_BTN_CANCEL) {
                    pThis->OnCancelClick();
                    return 0;
                }
            } else if (HIWORD(wParam) == LBN_SELCHANGE) {
                pThis->OnListSelectionChange();
                return 0;
            } else if (HIWORD(wParam) == LBN_DBLCLK) {
                // 双击直接连接
                pThis->OnConnectClick();
                return 0;
            }
            break;

        case WM_CLOSE:
            pThis->OnCancelClick();
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}
