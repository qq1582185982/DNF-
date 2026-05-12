package com.dnf.tunnel.android;

import java.util.ArrayList;
import java.util.List;

final class LeaseGrant {
    int status;
    String message;
    String virtualIp;
    String subnetMask;
    String gatewayIp;
    String serverVirtualIp;
    int mtu;
    int leaseSeconds;
    final List<String> routes = new ArrayList<>();
}
