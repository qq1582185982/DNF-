package com.dnf.tunnel.android;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

final class AndroidConfig {
    String apiHost = "";
    int apiPort = 0;
    String serverKey = "1";
    String clientId = "";

    boolean hasConnectionConfig() {
        return !apiHost.isEmpty() && apiPort > 0;
    }

    static AndroidConfig load(Context context) {
        AndroidConfig config = new AndroidConfig();
        try {
            InputStream input = context.getAssets().open("dnf_android_config.json");
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                while (true) {
                    int n = input.read(buffer);
                    if (n < 0) {
                        break;
                    }
                    if (n > 0) {
                        out.write(buffer, 0, n);
                    }
                }
                String jsonText = new String(out.toByteArray(), StandardCharsets.UTF_8);
                if (jsonText.startsWith("\uFEFF")) {
                    jsonText = jsonText.substring(1);
                }
                JSONObject json = new JSONObject(jsonText);
                config.apiHost = json.optString("config_api_url", "").trim();
                config.apiPort = json.optInt("config_api_port", 0);
                config.serverKey = json.optString("server_key", "1").trim();
                config.clientId = json.optString("client_id", "").trim();
                if (config.serverKey.isEmpty()) {
                    config.serverKey = "1";
                }
            } finally {
                input.close();
            }
        } catch (Exception ignored) {
        }
        return config;
    }
}
