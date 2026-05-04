DNF Windows Node Client

Use this package when a Windows Server 2022 machine should join as a node,
with behavior aligned to the Linux node client.

Files:
- DNF_Windows_Node_Client_v1.0.exe
- dnf-windows-node-client.conf.example
- run-windows-node-client.cmd
- LICENSE.wintun.txt

First run:
1. Extract the zip package.
2. Copy dnf-windows-node-client.conf.example to dnf-windows-node-client.conf,
   or run run-windows-node-client.cmd once to create it automatically.
3. Edit dnf-windows-node-client.conf:
   - api_url
   - api_port
   - server_virtual_ip or server_key
   - client_id
   - if_name
4. Run run-windows-node-client.cmd as Administrator.

Notes:
- Administrator permission is required for Wintun and route configuration.
- if_name is the Wintun adapter name on Windows.
- Logs are written under the log directory.
