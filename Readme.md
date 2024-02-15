# 执行命令

作为服务端执行 `./main server -c server.cfg -l server.log`

作为客户端执行  `./main client -c client.cfg -l client.log`

`./main -h/--help` 可以显示帮助信息

# 配置文件

使用 json 格式的配置文件

## server

~~~json
{
    "type":"server",
    "pidfile":"",
    "unixfile":"",
    "tcp":{
        "enable":true,
        "port":4567,
        "ip":"0.0.0.0"
    },
    "icmp":{
        "enable":true,
        "ip":"192.168.56.2",
        "breakTime":60
    },
    "quic":{
        "enable":true,
        "port":4567,
        "ip":"0.0.0.0",
        "certPath":"./public.cer",
        "keyPath":"./private.key",
        "shakeTime":5,
        "idleTime":30,
        "timeout":5
    },
    "tunnels":[
        {
            "tunnelName":"tunnel1",
            "passwd":"aaaaa",
            "deviceType":"tap",
            "deviceName":"tun1",
            "network":"10.0.0.1/24"
        },{
            "tunnelName":"tunnel2",
            "passwd":"bbbbb",
            "deviceType":"tap",
            "deviceName":"tun2",
            "network":"10.0.1.1/24"
        }
    ]
}
~~~

+ type：配置文件类型，这里是 server
+ pidfile：指定 pid 文件的路径以及文件名
+ unixfile：指定 unix 套接字文件的路径以及文件名（quic 协议无法接入 I\O 多路复用模型，通过 unix 套接字进行代理）
+ tcp：tcp 协议相关配置
  + enable：是否启用
  + port：监听端口
  + ip：监听地址
+ icmp：icmp 协议相关配置
  + enable：是否启用
  + ip：监听地址
  + breakTime：当通过 icmp 协议建立一条隧道之后，如果在 breakTime 秒内未收到客户端的任何报文，则删除该隧道
+ quic：quic 协议相关配置
  + enable：是否启用
  + port：监听端口
  + ip：监听地址
  + certPath、keyPath：证书公私钥配置
  + shakeTime：quic 协议 ssl 握手超时时间
  + idleTime：放弃连接之前的空闲时间
  + timeout：发送数据的超时时间
+ tunnels：隧道配置信息
  + tunnelName：隧道名称
  + passwd：密码，用于认证（认证未实现）
  + deviceType：tun 设备类型（tun/tap）
  + deviceName：设备名称
  + network：tun 设备地址

## client

~~~json
{
    "type":"client", 
    "protocol":"tcp",
    "pidfile":"./",
    "tcp":{
        "ip":"192.168.56.2",
        "port":4567,
        "keepalive":5,
        "timeout":5
    },
    "icmp":{
        "ip":"192.168.56.2",
        "identifier":4567,
        "keepalive":5
    },
    "quic":{
        "ip":"192.168.56.2",
        "quicUrl":"",
        "port":4567,
        "allowInSecure":true,
        "shakeTime":5,
        "idleTime":30,
        "timeout":5,
        "keepalive":5
    },
    "tunnelName":"tunnel1",
    "passwd":"aaaaa",
    "deviceType":"tap",
    "deviceName":"tun1",
    "network":"10.0.0.2/24"
}
~~~

+ type：配置文件类型，这里是 server
+ protocol：要使用的协议（tcp/quic/icmp）
+ pidfile：指定 pid 文件的路径以及文件名
+ tcp：tcp 协议相关配置
  + ip：远端 server 地址
  + port：远端 server 端口
  + keepalive：主动发送探测报文的频率（秒）
+ icmp：icmp 协议相关配置
  + ip：远端 server 地址
  + identifier：icmp 报文中的 id 字段
  + keepalive：主动发送探测报文的频率（秒）
+ quic：quic 协议相关配置
  + ip：远端 server 地址
  + quicUrl：远端 server url
  + port：远端 server 端口
  + allowInSecure：是否校验  server 端证书合法性（true 标识不校验）
  + shakeTime：quic 协议 ssl 握手超时时间
  + idleTime：放弃连接之前的空闲时间
  + timeout：发送数据的超时时间
  + keepalive：主动发送探测报文的频率（秒）
+ tunnelName：隧道名称
+ passwd：密码，用于认证（认证未实现）
+ deviceType：tun 设备类型（tun/tap）
+ deviceName：设备名称
+ network：tun 设备地址

# 系统变量

icmp 隧道在 server 端设置 `net.ipv4.icmp_echo_ignore_all=1`

quic 隧道在 server 端与 client 端设置 `net.core.rmem_max=2500000`

# 流量转发

```shell
——————————————————————                                                          ——————————————————————
|       client       |                                                          |       server       |
|                    |                                                          |                    |
|         tun0       |                                                          |      tun1          |
|      10.0.1.2      |                                                          |   10.0.1.1         |
|          |         |                                                          |        |           |
|          |         |                                                          |        |           |
|         eth0       |      gateway                                             |       eth1         |
|      192.168.1.2---|----192.168.1.1-----public network------------------------|---172.33.1.1       |
|                    |                                                          |                    |
——————————————————————                                                          ——————————————————————
```

假如已经建立了如上所示的拓扑，现在需要将 client 的流量发送到 server 并通过 server 进行转发，需要进行如下配置

## client

添加到 `172.33.1.1` 的路由避免到 `server` 的流量被代理

```shell
ip route add 172.33.1.1 via 192.168.1.1 dev eth0
```

添加到 `tun1` 的默认路由

```shell
ip route add default via 10.0.1.1 dev tun0
```

删除通过 `eth0` 的默认路由

```shell
ip route del default via 192.168.1.1 dev eth0
```

## server

打开内核的转发功能

```shell
sysctl -w net.ipv4.ip_forward=1
```

通过 `iptables` 实现流量转发功能

```shell
iptables -A FORWARD -i tun1 -o eth1 -j ACCEPT
iptables -A FORWARD -i eth1 -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
```

