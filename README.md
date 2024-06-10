# NSCAP_final
網路系統總整與實作期末
## 檔案說明
- socks_proxy.py: SOCKS5 代理伺服器
- test_cases.py: 13種測試cases
- udp_server.py: UDP 伺服器
- socks_proxy.log: 代理伺服器會記錄各種行為
## 使用說明
### ProxyChains 安裝與設定 (使用 Ubuntu 虛擬機)
1. 安裝: `sudo apt install proxychains`
2. 打開設定檔案: `sudo nano /etc/proxychains.conf`
3. 將設定檔更改如下:
```
# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted

dynamic_chain
#strict_chain
#random_chain

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Add proxy here (order matters, we use the first found working proxy).
# meanwile
# defaults set to "tor"
# socks4 127.0.0.1 9050
socks5 127.0.0.1 1080 user password
```
4. 在終端機測試: `proxychains wget http://example.com` (但記得先讓 server 運作，server 運作的指令在下方)
### 測試環境建立 (使用 Ubuntu 虛擬機)
1. 按照下圖的方式開啟4個終端機，分別輸入 `python3 socks_proxy.py`, `python3 udp_server.py`, `iperf3 -s -p 5201`
2. 最後一個終端機輸入 `test_cases.py n`，其中`n`代表測試代號，可輸入 1~13
   
![alt text](image.png)
