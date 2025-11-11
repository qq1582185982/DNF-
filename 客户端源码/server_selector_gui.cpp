/*
 * 服务器选择GUI窗口实现
 */

#include "server_selector_gui.h"
#include <commctrl.h>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

ServerSelectorGUI::ServerSelectorGUI()
    : hwnd(NULL), hInstance(GetModuleHandle(NULL)),
      selected_index(-1), user_confirmed(false), showing_log(false), is_connected(false),
      dialog_should_close(false) {
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
    dialog_should_close = false;

    // 初始化窗口
    if (!InitWindow()) {
        return false;
    }

    // 填充服务器列表
    PopulateServerList(last_server_id);

    // 显示窗口
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // 消息循环 - 持续运行直到明确要求关闭
    MSG msg;
    bool result_ready = false;
    bool result_value = false;

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        // 如果用户确认了服务器选择，记录结果但继续运行消息循环
        if (user_confirmed && !result_ready && selected_index >= 0 && selected_index < (int)servers.size()) {
            selected_server = servers[selected_index];
            result_ready = true;
            result_value = true;
            // 不退出循环，继续处理消息
        }

        // 只有当明确要求关闭对话框时才退出
        if (dialog_should_close || !IsWindow(hwnd)) {
            break;
        }
    }

    // 返回结果
    return result_ready ? result_value : false;
}

bool ServerSelectorGUI::InitWindow() {
    // 注册窗口类
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"DNFServerSelector";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(245, 247, 250));  // 现代浅灰背景

    // 先注销可能存在的旧类
    UnregisterClassW(L"DNFServerSelector", hInstance);
    RegisterClassW(&wc);

    // 创建窗口（居中显示，增大宽度以容纳3列）
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    int window_width = 800;  // 增大宽度
    int window_height = 620;
    int x = (screen_width - window_width) / 2;
    int y = (screen_height - window_height) / 2;

    hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST | WS_EX_LAYERED,  // 添加分层窗口支持阴影
        L"DNFServerSelector",
        L"选择服务器",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,  // 添加最小化按钮
        x, y, window_width, window_height,
        NULL, NULL, hInstance, this  // 传递this指针
    );

    if (!hwnd) {
        return false;
    }

    // 设置窗口透明度和阴影效果
    SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);

    // 设置窗口数据（存储this指针）
    SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)this);

    // 创建控件 - 现代化扁平设计
    // 1. 标题文本（更现代的样式）
    HWND hTitle = CreateWindowW(
        L"STATIC", L"选择游戏服务器",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        30, 25, 740, 40,
        hwnd, NULL, hInstance, NULL
    );

    // 设置标题字体（轻量，现代）
    HFONT hTitleFont = CreateFont(
        32, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // 2. 分割线
    HWND hDivider = CreateWindowW(
        L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        30, 75, 740, 2,
        hwnd, NULL, hInstance, NULL
    );

    // 3. 服务器按钮将在PopulateServerList中动态创建
    // 预留空间: 30, 95, 740, 320

    // 4. 下载地址区域标签
    HWND hLabel = CreateWindowW(
        L"STATIC", L"客户端下载地址",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        30, 430, 250, 28,
        hwnd, (HMENU)IDC_STATIC_LABEL, hInstance, NULL
    );

    // 设置标签字体（加大字体）
    HFONT hLabelFont = CreateFont(
        20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hLabel, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

    // 5. 下载地址文本框（现代扁平样式）
    HWND hEdit = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY | ES_AUTOHSCROLL,
        30, 463, 740, 38,
        hwnd, (HMENU)IDC_EDIT_DOWNLOAD, hInstance, NULL
    );

    // 设置文本框字体（加大字体）
    HFONT hEditFont = CreateFont(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hEditFont, TRUE);

    // 6. 连接按钮（现代扁平设计，主色调）
    HWND hBtnConnect = CreateWindowW(
        L"BUTTON", L"连接服务器",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        30, 520, 355, 48,
        hwnd, (HMENU)IDC_BTN_CONNECT, hInstance, NULL
    );

    // 设置按钮字体
    HFONT hButtonFont = CreateFont(
        18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hBtnConnect, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    // 7. 取消按钮（次要按钮）
    HWND hBtnCancel = CreateWindowW(
        L"BUTTON", L"取消",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        415, 520, 355, 48,
        hwnd, (HMENU)IDC_BTN_CANCEL, hInstance, NULL
    );
    SendMessage(hBtnCancel, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    // 8. "查看日志"按钮（放在标题右侧）
    HWND hBtnShowLog = CreateWindowW(
        L"BUTTON", L"查看日志",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        650, 25, 120, 40,
        hwnd, (HMENU)IDC_BTN_SHOW_LOG, hInstance, NULL
    );
    HFONT hSmallFont = CreateFont(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hBtnShowLog, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    // 9. 日志文本框（多行只读，初始隐藏）
    HWND hEditLog = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_BORDER | ES_LEFT | ES_READONLY | ES_MULTILINE |
        ES_AUTOVSCROLL | WS_VSCROLL,
        30, 95, 740, 405,
        hwnd, (HMENU)IDC_EDIT_LOG, hInstance, NULL
    );
    SendMessage(hEditLog, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    // 10. "返回"按钮（初始隐藏）
    HWND hBtnBack = CreateWindowW(
        L"BUTTON", L"返回",
        WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
        30, 520, 740, 48,
        hwnd, (HMENU)IDC_BTN_BACK, hInstance, NULL
    );
    SendMessage(hBtnBack, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    return true;
}

void ServerSelectorGUI::PopulateServerList(int last_server_id) {
    // 清除旧按钮
    for (HWND btn : server_buttons) {
        if (btn) {
            DestroyWindow(btn);
        }
    }
    server_buttons.clear();

    // 创建按钮字体
    HFONT hButtonFont = CreateFont(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );

    // 网格布局参数
    const int cols = 3;           // 每行3个
    const int start_x = 30;
    const int start_y = 95;
    const int btn_width = 235;    // 按钮宽度
    const int btn_height = 60;    // 按钮高度
    const int gap_x = 10;         // 水平间距
    const int gap_y = 10;         // 垂直间距

    int default_index = -1;

    // 创建服务器按钮
    for (size_t i = 0; i < servers.size(); i++) {
        int row = i / cols;
        int col = i % cols;

        int x = start_x + col * (btn_width + gap_x);
        int y = start_y + row * (btn_height + gap_y);

        HWND hBtn = CreateWindowW(
            L"BUTTON", servers[i].name.c_str(),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT | BS_MULTILINE,
            x, y, btn_width, btn_height,
            hwnd, (HMENU)(IDC_SERVER_BTN_BASE + i), hInstance, NULL
        );

        SendMessage(hBtn, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
        server_buttons.push_back(hBtn);

        // 如果是上次选择的服务器，记录索引
        if (servers[i].id == last_server_id) {
            default_index = i;
        }
    }

    // 如果有上次选择，自动选中并显示信息
    if (default_index >= 0) {
        selected_index = default_index;
        UpdateServerInfo(default_index);
        // 高亮显示（可选：设置焦点）
        if (default_index < (int)server_buttons.size()) {
            SetFocus(server_buttons[default_index]);
        }
    }
}

void ServerSelectorGUI::UpdateServerInfo(int index) {
    if (index < 0 || index >= (int)servers.size()) {
        SetDlgItemTextW(hwnd, IDC_EDIT_DOWNLOAD, L"");
        return;
    }

    const ServerInfo& info = servers[index];

    // 将 UTF-8 字符串转换为宽字符（支持中文URL）
    if (info.download_url.empty()) {
        SetDlgItemTextW(hwnd, IDC_EDIT_DOWNLOAD, L"");
    } else {
        int len = MultiByteToWideChar(CP_UTF8, 0, info.download_url.c_str(), -1, NULL, 0);
        if (len > 0) {
            wchar_t* wbuf = new wchar_t[len];
            MultiByteToWideChar(CP_UTF8, 0, info.download_url.c_str(), -1, wbuf, len);
            SetDlgItemTextW(hwnd, IDC_EDIT_DOWNLOAD, wbuf);
            delete[] wbuf;
        } else {
            // 转换失败，尝试直接使用 ANSI（适用于纯ASCII URL）
            SetDlgItemTextA(hwnd, IDC_EDIT_DOWNLOAD, info.download_url.c_str());
        }
    }
}

void ServerSelectorGUI::OnConnectClick() {
    if (selected_index < 0 || selected_index >= (int)servers.size()) {
        MessageBoxW(hwnd, L"请先选择一个服务器！", L"提示", MB_OK | MB_ICONWARNING);
        return;
    }

    user_confirmed = true;
    is_connected = true;  // 标记为已连接

    // 切换到日志页面，而不是关闭窗口
    ShowLogPage();

    // 显示连接信息
    std::wstring server_name = servers[selected_index].name;
    AppendLog(L"=== 开始连接 ===\r\n");
    AppendLog(L"服务器: " + server_name + L"\r\n");
    AppendLog(L"正在建立连接...\r\n\r\n");
}

void ServerSelectorGUI::OnCancelClick() {
    selected_index = -1;
    user_confirmed = false;
    dialog_should_close = true;

    // 关闭窗口
    DestroyWindow(hwnd);
    PostQuitMessage(0);
}

void ServerSelectorGUI::OnListSelectionChange() {
    // 保留此函数以保持兼容性，但不再使用
}

void ServerSelectorGUI::OnServerButtonClick(int server_index) {
    if (server_index >= 0 && server_index < (int)servers.size()) {
        selected_index = server_index;
        UpdateServerInfo(server_index);

        // 视觉反馈：高亮选中的按钮
        for (size_t i = 0; i < server_buttons.size(); i++) {
            if ((int)i == server_index) {
                // 选中状态：设置焦点
                SetFocus(server_buttons[i]);
            }
        }
    }
}

void ServerSelectorGUI::ShowLogPage() {
    showing_log = true;

    // 隐藏服务器选择页面的控件
    for (HWND btn : server_buttons) {
        ShowWindow(btn, SW_HIDE);
    }
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LABEL), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_DOWNLOAD), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CONNECT), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CANCEL), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_SHOW_LOG), SW_HIDE);

    // 显示日志页面的控件
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_LOG), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_BACK), SW_SHOW);

    // 添加初始日志
    AppendLog(L"=== 日志系统已启动 ===\r\n");
    AppendLog(L"等待连接...\r\n");
}

void ServerSelectorGUI::ShowServerPage() {
    showing_log = false;

    // 显示服务器选择页面的控件
    for (HWND btn : server_buttons) {
        ShowWindow(btn, SW_SHOW);
    }
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LABEL), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_DOWNLOAD), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CONNECT), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CANCEL), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_SHOW_LOG), SW_SHOW);

    // 隐藏日志页面的控件
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_LOG), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_BACK), SW_HIDE);
}

void ServerSelectorGUI::AppendLog(const std::wstring& message) {
    HWND hEditLog = GetDlgItem(hwnd, IDC_EDIT_LOG);
    if (!hEditLog) return;

    // 获取当前文本长度
    int len = GetWindowTextLengthW(hEditLog);

    // 将光标移到末尾
    SendMessageW(hEditLog, EM_SETSEL, len, len);

    // 追加文本
    SendMessageW(hEditLog, EM_REPLACESEL, FALSE, (LPARAM)message.c_str());

    // 滚动到底部
    SendMessageW(hEditLog, EM_SCROLLCARET, 0, 0);
}

// 公共方法：添加日志（供外部调用）
void ServerSelectorGUI::AddLog(const std::wstring& message) {
    AppendLog(message);
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
        case WM_DRAWITEM: {
            // 自定义绘制ListBox项（现代扁平风格）
            LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
            if (lpDIS->CtlID == IDC_SERVER_LIST) {
                // 获取设备上下文
                HDC hDC = lpDIS->hDC;
                RECT rcItem = lpDIS->rcItem;

                // 判断是否选中
                bool isSelected = (lpDIS->itemState & ODS_SELECTED) != 0;
                bool isFocused = (lpDIS->itemState & ODS_FOCUS) != 0;

                // 设置背景颜色（现代扁平设计）
                COLORREF bgColor;
                COLORREF textColor;

                if (isSelected) {
                    // 选中状态：现代蓝色（类似Windows 11）
                    bgColor = RGB(0, 120, 215);
                    textColor = RGB(255, 255, 255);
                } else {
                    // 未选中状态：纯白背景
                    bgColor = RGB(255, 255, 255);
                    textColor = RGB(32, 32, 32);
                }

                // 填充背景
                HBRUSH hBrush = CreateSolidBrush(bgColor);
                FillRect(hDC, &rcItem, hBrush);
                DeleteObject(hBrush);

                // 绘制聚焦框（使用现代虚线边框）
                if (isFocused && !isSelected) {
                    HPEN hPen = CreatePen(PS_DOT, 1, RGB(0, 120, 215));
                    HPEN hOldPen = (HPEN)SelectObject(hDC, hPen);
                    HBRUSH hOldBrush = (HBRUSH)SelectObject(hDC, GetStockObject(NULL_BRUSH));

                    Rectangle(hDC, rcItem.left + 2, rcItem.top + 2,
                             rcItem.right - 2, rcItem.bottom - 2);

                    SelectObject(hDC, hOldPen);
                    SelectObject(hDC, hOldBrush);
                    DeleteObject(hPen);
                }

                // 获取文本
                if (lpDIS->itemID != (UINT)-1) {
                    wchar_t text[256];
                    SendMessageW(lpDIS->hwndItem, LB_GETTEXT, lpDIS->itemID, (LPARAM)text);

                    // 设置文本属性
                    SetBkMode(hDC, TRANSPARENT);
                    SetTextColor(hDC, textColor);

                    // 使用控件的字体
                    HFONT hFont = (HFONT)SendMessageW(lpDIS->hwndItem, WM_GETFONT, 0, 0);
                    HFONT hOldFont = (HFONT)SelectObject(hDC, hFont);

                    // 绘制文本（带左侧内边距）
                    RECT rcText = rcItem;
                    rcText.left += 15;  // 左侧内边距
                    rcText.right -= 15; // 右侧内边距

                    DrawTextW(hDC, text, -1, &rcText,
                             DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

                    SelectObject(hDC, hOldFont);
                }

                return TRUE;
            }
            break;
        }

        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED) {
                int ctrl_id = LOWORD(wParam);
                if (ctrl_id == IDC_BTN_CONNECT) {
                    pThis->OnConnectClick();
                    return 0;
                } else if (ctrl_id == IDC_BTN_CANCEL) {
                    pThis->OnCancelClick();
                    return 0;
                } else if (ctrl_id == IDC_BTN_SHOW_LOG) {
                    // 切换到日志页面
                    pThis->ShowLogPage();
                    return 0;
                } else if (ctrl_id == IDC_BTN_BACK) {
                    // 返回服务器选择页面
                    if (pThis->is_connected) {
                        // 如果已连接，提示用户
                        int result = MessageBoxW(hwnd,
                                                L"当前已建立连接\n\n返回服务器选择页面将断开连接\n确定要继续吗？",
                                                L"确认",
                                                MB_YESNO | MB_ICONQUESTION);
                        if (result == IDYES) {
                            pThis->is_connected = false;
                            pThis->user_confirmed = false;
                            pThis->ShowServerPage();
                        }
                    } else {
                        // 未连接，直接返回
                        pThis->ShowServerPage();
                    }
                    return 0;
                } else if (ctrl_id >= IDC_SERVER_BTN_BASE && ctrl_id < IDC_SERVER_BTN_BASE + 100) {
                    // 服务器按钮点击
                    int server_index = ctrl_id - IDC_SERVER_BTN_BASE;
                    pThis->OnServerButtonClick(server_index);
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
