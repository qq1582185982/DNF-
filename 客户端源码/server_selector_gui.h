/*
 * 服务器选择GUI窗口
 * 类似DNF频道选择的风格
 */

#ifndef SERVER_SELECTOR_GUI_H
#define SERVER_SELECTOR_GUI_H

#include <windows.h>
#include <vector>
#include <string>
#include "http_client.h"

// 窗口控件ID
#define IDC_SERVER_LIST    1001
#define IDC_BTN_CONNECT    1002
#define IDC_BTN_CANCEL     1003
#define IDC_STATIC_LABEL   1004  // "下载地址:" 标签
#define IDC_EDIT_DOWNLOAD  1005  // 下载地址文本框（可复制）
#define IDC_SERVER_BTN_BASE 2000  // 服务器按钮ID起始值 (2000+索引)

// 服务器选择器类
class ServerSelectorGUI {
public:
    ServerSelectorGUI();
    ~ServerSelectorGUI();

    // 显示服务器选择窗口（模态对话框）
    // servers: 服务器列表
    // last_server_id: 上次选择的服务器ID（用于高亮显示,如果=0则不高亮）
    // selected_server: 输出选中的服务器
    // 返回: 用户是否选择了服务器（true=选择了, false=点击了取消）
    bool ShowDialog(const std::vector<ServerInfo>& servers,
                   int last_server_id,
                   ServerInfo& selected_server);

private:
    HWND hwnd;
    HINSTANCE hInstance;
    std::vector<ServerInfo> servers;
    int selected_index;
    bool user_confirmed;
    std::vector<HWND> server_buttons;  // 存储服务器按钮句柄

    // 窗口过程函数
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // 初始化窗口
    bool InitWindow();

    // 填充服务器列表
    void PopulateServerList(int last_server_id);

    // 更新服务器详情显示
    void UpdateServerInfo(int index);

    // 处理连接按钮点击
    void OnConnectClick();

    // 处理取消按钮点击
    void OnCancelClick();

    // 处理列表选择变化
    void OnListSelectionChange();

    // 处理服务器按钮点击
    void OnServerButtonClick(int server_index);
};

#endif // SERVER_SELECTOR_GUI_H
