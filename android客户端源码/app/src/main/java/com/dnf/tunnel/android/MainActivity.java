package com.dnf.tunnel.android;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST_CODE = 1001;

    private EditText apiHostEdit;
    private EditText apiPortEdit;
    private EditText serverKeyEdit;
    private EditText clientIdEdit;
    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        loadPrefs();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpnService();
        }
    }

    private void buildUi() {
        ScrollView scrollView = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(16));
        scrollView.addView(root);

        TextView title = new TextView(this);
        title.setText("DNF Android Client");
        title.setTextSize(22);
        title.setGravity(Gravity.START);
        root.addView(title, matchWidth());

        apiHostEdit = addInput(root, "API Host", InputType.TYPE_CLASS_TEXT);
        apiPortEdit = addInput(root, "API Port", InputType.TYPE_CLASS_NUMBER);
        serverKeyEdit = addInput(root, "Server Key", InputType.TYPE_CLASS_TEXT);
        clientIdEdit = addInput(root, "Client ID", InputType.TYPE_CLASS_TEXT);

        Button loadServersButton = new Button(this);
        loadServersButton.setText("获取节点");
        loadServersButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                loadServers();
            }
        });
        root.addView(loadServersButton, matchWidth());

        Button startButton = new Button(this);
        startButton.setText("启动 VPN");
        startButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestStartVpn();
            }
        });
        root.addView(startButton, matchWidth());

        Button stopButton = new Button(this);
        stopButton.setText("停止 VPN");
        stopButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                stopVpn();
            }
        });
        root.addView(stopButton, matchWidth());

        statusText = new TextView(this);
        statusText.setTextSize(14);
        statusText.setPadding(0, dp(12), 0, 0);
        statusText.setText("relay-only 第一版，不启用对等直连。");
        root.addView(statusText, matchWidth());

        setContentView(scrollView);
    }

    private EditText addInput(LinearLayout root, String hint, int inputType) {
        EditText editText = new EditText(this);
        editText.setHint(hint);
        editText.setSingleLine(true);
        editText.setInputType(inputType);
        root.addView(editText, matchWidth());
        return editText;
    }

    private void loadPrefs() {
        SharedPreferences prefs = prefs();
        apiHostEdit.setText(prefs.getString("api_host", ""));
        apiPortEdit.setText(prefs.getString("api_port", ""));
        serverKeyEdit.setText(prefs.getString("server_key", "1"));
        String defaultClientId = "android-" + Settings.Secure.getString(getContentResolver(),
                                                                        Settings.Secure.ANDROID_ID);
        clientIdEdit.setText(prefs.getString("client_id", defaultClientId));
    }

    private void savePrefs() {
        prefs().edit()
                .putString("api_host", apiHost())
                .putString("api_port", apiPortEdit.getText().toString().trim())
                .putString("server_key", serverKey())
                .putString("client_id", clientId())
                .apply();
    }

    private void loadServers() {
        savePrefs();
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
                            statusText.setText("获取节点失败: " + e.getMessage());
                        }
                    });
                }
            }
        }, "dnf-android-load-servers").start();
    }

    private void showServers(List<ServerInfo> servers) {
        if (servers == null || servers.isEmpty()) {
            statusText.setText("没有节点。");
            return;
        }
        StringBuilder text = new StringBuilder();
        text.append("节点列表:\n");
        for (ServerInfo server : servers) {
            text.append(server.id)
                    .append("  ")
                    .append(server.name)
                    .append("  ")
                    .append(server.serverVirtualIp)
                    .append("  ")
                    .append(server.tunnelServerIp)
                    .append(":")
                    .append(server.tunnelPort)
                    .append('\n');
        }
        statusText.setText(text.toString());
    }

    private void requestStartVpn() {
        savePrefs();
        if (apiHost().isEmpty() || apiPort() <= 0 || clientId().isEmpty()) {
            Toast.makeText(this, "请填写 API Host / API Port / Client ID", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent prepareIntent = VpnService.prepare(this);
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, VPN_REQUEST_CODE);
        } else {
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
        statusText.setText("VPN 已请求启动。");
    }

    private void stopVpn() {
        Intent intent = new Intent(this, DnfVpnService.class);
        intent.setAction(DnfVpnService.ACTION_STOP);
        startService(intent);
        statusText.setText("VPN 已请求停止。");
    }

    private String apiHost() {
        return apiHostEdit.getText().toString().trim();
    }

    private int apiPort() {
        try {
            return Integer.parseInt(apiPortEdit.getText().toString().trim());
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private String serverKey() {
        return serverKeyEdit.getText().toString().trim();
    }

    private String clientId() {
        return clientIdEdit.getText().toString().trim().replaceAll("\\s+", "_");
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

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}
