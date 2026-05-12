package com.dnf.tunnel.android;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST_CODE = 1001;
    private static final int SERVER_GRID_COLUMNS = 2;

    private ScrollView selectionScrollView;
    private ScrollView logScrollView;
    private LinearLayout serverGrid;
    private TextView statusText;
    private TextView logText;
    private Button startButton;

    private String apiHostValue = "";
    private int apiPortValue = 0;
    private String defaultServerKey = "1";
    private String selectedServerKey = "";
    private String clientIdValue = "";
    private final List<ServerInfo> currentServers = new ArrayList<>();
    private final SimpleDateFormat logTimeFormat = new SimpleDateFormat("HH:mm:ss", Locale.US);
    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || !DnfVpnService.ACTION_STATUS.equals(intent.getAction())) {
                return;
            }
            appendLog(intent.getStringExtra(DnfVpnService.EXTRA_STATUS_MESSAGE));
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        loadPrefs();
        loadServers();
    }

    @Override
    protected void onStart() {
        super.onStart();
        IntentFilter filter = new IntentFilter(DnfVpnService.ACTION_STATUS);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(statusReceiver, filter);
        }
    }

    @Override
    protected void onStop() {
        try {
            unregisterReceiver(statusReceiver);
        } catch (IllegalArgumentException ignored) {
        }
        super.onStop();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            appendLog("系统 VPN 授权已通过。");
            startVpnService();
        } else if (requestCode == VPN_REQUEST_CODE) {
            appendLog("系统 VPN 授权已取消。");
        }
    }

    private void buildUi() {
        FrameLayout pageHost = new FrameLayout(this);
        selectionScrollView = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(16));
        selectionScrollView.addView(root);

        TextView title = new TextView(this);
        title.setText("选择游戏服务器");
        title.setTextSize(24);
        title.setTextColor(Color.rgb(55, 55, 55));
        title.setGravity(Gravity.START);
        root.addView(title, matchWidth());

        statusText = new TextView(this);
        statusText.setTextSize(14);
        statusText.setTextColor(Color.rgb(90, 90, 90));
        statusText.setPadding(0, dp(8), 0, dp(4));
        statusText.setText("正在准备节点列表...");
        root.addView(statusText, matchWidth());

        serverGrid = new LinearLayout(this);
        serverGrid.setOrientation(LinearLayout.VERTICAL);
        root.addView(serverGrid, matchWidth());

        Button refreshButton = new Button(this);
        refreshButton.setText("刷新节点");
        refreshButton.setAllCaps(false);
        refreshButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                loadServers();
            }
        });
        root.addView(refreshButton, matchWidth());

        startButton = new Button(this);
        startButton.setText("连接服务器");
        startButton.setAllCaps(false);
        startButton.setEnabled(false);
        startButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestStartVpn();
            }
        });
        root.addView(startButton, matchWidth());

        Button stopButton = new Button(this);
        stopButton.setText("停止 VPN");
        stopButton.setAllCaps(false);
        stopButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                stopVpn();
            }
        });
        root.addView(stopButton, matchWidth());

        buildLogUi();
        logScrollView.setVisibility(View.GONE);
        pageHost.addView(selectionScrollView, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        pageHost.addView(logScrollView, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        setContentView(pageHost);
    }

    private void buildLogUi() {
        logScrollView = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(16));
        logScrollView.addView(root);

        TextView title = new TextView(this);
        title.setText("连接日志");
        title.setTextSize(24);
        title.setTextColor(Color.rgb(55, 55, 55));
        title.setGravity(Gravity.START);
        root.addView(title, matchWidth());

        logText = new TextView(this);
        logText.setTextSize(13);
        logText.setTextColor(Color.rgb(40, 40, 40));
        logText.setTypeface(Typeface.MONOSPACE);
        logText.setPadding(dp(10), dp(10), dp(10), dp(10));
        logText.setBackgroundColor(Color.rgb(245, 247, 250));
        root.addView(logText, matchWidth());

        Button stopButton = new Button(this);
        stopButton.setText("停止 VPN");
        stopButton.setAllCaps(false);
        stopButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                stopVpn();
            }
        });
        root.addView(stopButton, matchWidth());

        Button backButton = new Button(this);
        backButton.setText("返回服务器选择");
        backButton.setAllCaps(false);
        backButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSelectionPage();
            }
        });
        root.addView(backButton, matchWidth());
    }

    private void loadPrefs() {
        SharedPreferences prefs = prefs();
        AndroidConfig embeddedConfig = AndroidConfig.load(this);
        String defaultClientId = "android-" + Settings.Secure.getString(getContentResolver(),
                                                                        Settings.Secure.ANDROID_ID);
        if (embeddedConfig.hasConnectionConfig()) {
            apiHostValue = embeddedConfig.apiHost;
            apiPortValue = embeddedConfig.apiPort;
            defaultServerKey = embeddedConfig.serverKey;
            clientIdValue = embeddedConfig.clientId.isEmpty() ? defaultClientId : embeddedConfig.clientId;
        } else {
            apiHostValue = prefs.getString("api_host", "");
            apiPortValue = parsePort(prefs.getString("api_port", ""));
            defaultServerKey = prefs.getString("server_key", "1");
            clientIdValue = prefs.getString("client_id", defaultClientId);
        }
        selectedServerKey = prefs.getString("selected_server_key", defaultServerKey);
    }

    private void savePrefs() {
        prefs().edit()
                .putString("api_host", apiHostValue)
                .putString("api_port", apiPortValue > 0 ? Integer.toString(apiPortValue) : "")
                .putString("server_key", defaultServerKey)
                .putString("selected_server_key", selectedServerKey)
                .putString("client_id", clientId())
                .apply();
    }

    private void loadServers() {
        if (apiHost().isEmpty() || apiPort() <= 0) {
            serverGrid.removeAllViews();
            startButton.setEnabled(false);
            statusText.setText("当前 APK 未内置配置，请使用 GitHub 自动构建生成带配置客户端。");
            return;
        }

        serverGrid.removeAllViews();
        startButton.setEnabled(false);
        statusText.setText("正在获取节点...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    ControlClient client = new ControlClient(apiHost(), apiPort());
                    final List<ServerInfo> servers = client.getServers();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            showServers(servers);
                        }
                    });
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            currentServers.clear();
                            serverGrid.removeAllViews();
                            startButton.setEnabled(false);
                            statusText.setText("获取节点失败，请检查网络或配置服务器。");
                        }
                    });
                }
            }
        }, "dnf-android-load-servers").start();
    }

    private void showServers(List<ServerInfo> servers) {
        currentServers.clear();
        serverGrid.removeAllViews();
        if (servers == null || servers.isEmpty()) {
            startButton.setEnabled(false);
            statusText.setText("没有可用节点。");
            return;
        }

        currentServers.addAll(servers);
        ServerInfo selected = findServerByKey(selectedServerKey);
        if (selected == null) {
            selected = findServerByKey(defaultServerKey);
        }
        if (selected == null) {
            selected = currentServers.get(0);
        }
        selectedServerKey = selected.serverKey();
        renderServerButtons();
        startButton.setEnabled(true);
        updateSelectedStatus(selected);
        savePrefs();
    }

    private void renderServerButtons() {
        serverGrid.removeAllViews();
        for (int i = 0; i < currentServers.size(); i += SERVER_GRID_COLUMNS) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            serverGrid.addView(row, matchWidth());

            for (int col = 0; col < SERVER_GRID_COLUMNS; ++col) {
                final int index = i + col;
                if (index >= currentServers.size()) {
                    TextView spacer = new TextView(this);
                    row.addView(spacer, weightedColumn());
                    continue;
                }

                final ServerInfo server = currentServers.get(index);
                Button button = new Button(this);
                button.setText(serverLabel(server));
                button.setTextSize(14);
                button.setAllCaps(false);
                button.setMinHeight(dp(52));
                button.setGravity(Gravity.CENTER);
                if (server.serverKey().equals(selectedServerKey)) {
                    button.setTextColor(Color.WHITE);
                    button.setBackgroundColor(Color.rgb(37, 99, 235));
                } else {
                    button.setTextColor(Color.rgb(35, 35, 35));
                    button.setBackgroundColor(Color.rgb(230, 232, 235));
                }
                button.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        selectServer(server);
                    }
                });
                row.addView(button, weightedColumn());
            }
        }
    }

    private void selectServer(ServerInfo server) {
        selectedServerKey = server.serverKey();
        renderServerButtons();
        updateSelectedStatus(server);
        savePrefs();
    }

    private void updateSelectedStatus(ServerInfo server) {
        statusText.setText("已选择：" + serverLabel(server));
    }

    private ServerInfo findServerByKey(String key) {
        if (key == null || key.trim().isEmpty()) {
            return null;
        }
        for (ServerInfo server : currentServers) {
            if (key.trim().equals(server.serverKey())) {
                return server;
            }
        }
        return null;
    }

    private static String serverLabel(ServerInfo server) {
        if (server.name != null && !server.name.trim().isEmpty()) {
            return server.name.trim();
        }
        return "服务器 " + server.serverKey();
    }

    private void showLogPage() {
        selectionScrollView.setVisibility(View.GONE);
        logScrollView.setVisibility(View.VISIBLE);
    }

    private void showSelectionPage() {
        logScrollView.setVisibility(View.GONE);
        selectionScrollView.setVisibility(View.VISIBLE);
    }

    private void resetLog(String firstLine) {
        if (logText != null) {
            logText.setText("");
        }
        appendLog(firstLine);
    }

    private void appendLog(String message) {
        if (message == null || message.trim().isEmpty() || logText == null) {
            return;
        }
        String line = logTimeFormat.format(new Date()) + "  " + message.trim() + "\n";
        logText.append(line);
        if (logScrollView != null) {
            logScrollView.post(new Runnable() {
                @Override
                public void run() {
                    logScrollView.fullScroll(View.FOCUS_DOWN);
                }
            });
        }
    }

    private void requestStartVpn() {
        if (apiHost().isEmpty() || apiPort() <= 0) {
            Toast.makeText(this, "当前 APK 未内置配置服务器", Toast.LENGTH_SHORT).show();
            return;
        }
        if (selectedServerKey.isEmpty()) {
            Toast.makeText(this, "请先选择服务器", Toast.LENGTH_SHORT).show();
            return;
        }
        if (clientId().isEmpty()) {
            Toast.makeText(this, "客户端 ID 无效", Toast.LENGTH_SHORT).show();
            return;
        }
        savePrefs();
        ServerInfo selected = findServerByKey(selectedServerKey);
        showLogPage();
        resetLog("准备连接：" + (selected == null ? "当前服务器" : serverLabel(selected)));
        Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            appendLog("正在请求系统 VPN 授权...");
            startActivityForResult(prepareIntent, VPN_REQUEST_CODE);
        } else {
            appendLog("系统 VPN 已授权。");
            startVpnService();
        }
    }

    private void startVpnService() {
        Intent intent = new Intent(this, DnfVpnService.class);
        intent.setAction(DnfVpnService.ACTION_START);
        intent.putExtra(DnfVpnService.EXTRA_API_HOST, apiHost());
        intent.putExtra(DnfVpnService.EXTRA_API_PORT, apiPort());
        intent.putExtra(DnfVpnService.EXTRA_SERVER_KEY, serverKey());
        intent.putExtra(DnfVpnService.EXTRA_CLIENT_ID, clientId());
        startService(intent);
        ServerInfo selected = findServerByKey(selectedServerKey);
        appendLog("VPN 服务启动请求已发送：" + (selected == null ? "当前服务器" : serverLabel(selected)));
        statusText.setText("VPN 已请求启动：" + (selected == null ? "当前服务器" : serverLabel(selected)));
    }

    private void stopVpn() {
        Intent intent = new Intent(this, DnfVpnService.class);
        intent.setAction(DnfVpnService.ACTION_STOP);
        startService(intent);
        appendLog("VPN 停止请求已发送。");
        statusText.setText("VPN 已请求停止。");
    }

    private String apiHost() {
        return apiHostValue == null ? "" : apiHostValue.trim();
    }

    private int apiPort() {
        return apiPortValue;
    }

    private String serverKey() {
        return selectedServerKey == null ? "" : selectedServerKey.trim();
    }

    private String clientId() {
        return clientIdValue == null ? "" : clientIdValue.trim().replaceAll("\\s+", "_");
    }

    private SharedPreferences prefs() {
        return getSharedPreferences("dnf_android_client", MODE_PRIVATE);
    }

    private LinearLayout.LayoutParams matchWidth() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(8), 0, 0);
        return params;
    }

    private LinearLayout.LayoutParams weightedColumn() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1.0f);
        params.setMargins(dp(4), 0, dp(4), 0);
        return params;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static int parsePort(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception ignored) {
            return 0;
        }
    }
}
