package com.dnf.tunnel.android;

final class ServerInfo {
    int id;
    String name;
    String serverVirtualIp;
    String tunnelServerIp;
    int tunnelPort;
    String virtualSubnet;
    String virtualGateway;
    int leaseSeconds;

    String serverKey() {
        return Integer.toString(id);
    }
}
