# Finding Public and Private IP Addresses on macOS, Windows, and Linux

## Understanding IP Addresses

- **Private IP Address:** Used within a local network (e.g., 192.168.x.x, 10.x.x.x). Devices use private IPs to communicate with each other inside the same network.
- **Public IP Address:** Assigned by your Internet Service Provider (ISP) and used to communicate with devices on the internet. It is unique across the internet.

***

## Finding IP Addresses on macOS

### Finding Private IP Address

1. Open **System Preferences**.
2. Click **Network**.
3. Select your active network connection (Wi-Fi or Ethernet).
4. Your private IP address will be displayed under the connection status.

Or, use Terminal:

```bash
ipconfig getifaddr en0  # For Wi-Fi interface
ipconfig getifaddr en1  # For Ethernet or other interfaces
```


### Finding Public IP Address

Open Terminal and run:

```bash
curl ifconfig.me
```

Or visit a website in your browser like [https://whatismyipaddress.com](https://whatismyipaddress.com)

***

## Finding IP Addresses on Windows

### Finding Private IP Address

1. Open **Command Prompt** (press `Win + R`, type `cmd`, press Enter).
2. Run the command:
```cmd
ipconfig
```

3. Look under your active network adapter for the "IPv4 Address" field. This is your private IP.

### Finding Public IP Address

1. Open Command Prompt.
2. Run:
```powershell
nslookup myip.opendns.com resolver1.opendns.com
```

Alternatively, visit [https://whatismyipaddress.com](https://whatismyipaddress.com) in a web browser.

***

## Finding IP Addresses on Linux

### Finding Private IP Address

Open a terminal and run:

```bash
ip addr show
```

Or a simpler command targeting active interfaces:

```bash
hostname -I
```

Look for the IP address associated with your network interface (e.g., eth0, wlan0).

### Finding Public IP Address

Run the command:

```bash
curl ifconfig.me
```

Or use other web services:

```bash
curl icanhazip.com
```


***

## Summary Table

| Operating System | Private IP Command(s) | Public IP Command(s) |
| :-- | :-- | :-- |
| macOS | `ipconfig getifaddr en0` | `curl ifconfig.me` |
| Windows | `ipconfig` | `nslookup myip.opendns.com resolver1.opendns.com` |
| Linux | `ip addr show` or `hostname -I` | `curl ifconfig.me` or `curl icanhazip.com` |


***

## Additional Notes

- Private IPs are generally assigned by your router using DHCP.
- Public IP can change based on your ISP or network.
- Using terminal commands is quick, but websites make it easy if you prefer a graphical interface.
- To find the IP address of a particular network interface, identify the interface name (`en0`, `wlan0`, `eth0` etc.) before using commands.



