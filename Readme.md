# Command

`./main server -c server.cfg -l server.log` run as server or `./main client -c client.cfg -l client.log` run as client.

# Config File

 Use the json format file as the configuration file.

## config file for server

~~~json
{
    "type":"server",
    "tcp":{
        "enable":true,
        "port":4567,
        "ip":"0.0.0.0",
        "timeout":5
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

## config file for client

~~~json
{
    "type":"client", 
    "protocol":"tcp",
    "tcp":{
        "ip":"192.168.56.2",
        "port":4567,
        "keepalive":5,
        "timeout":5
    },
    "icmp":{
        "ip":"192.168.56.2",
        "identifier":4567,
        "timeout":5,
        "keepalive":5,
        "retryTimes":5,
        "breakTime":60
    },
    "quic":{
        "ip":"192.168.56.2",
        "quicUrl":"",
        "port":4567,
        "allowInSecure":true,
        "shakeTime":5,
        "idleTime":30,
        "timeout":5
    },
    "tunnelName":"tunnel1",
    "passwd":"aaaaa",
    "deviceType":"tap",
    "deviceName":"tun1",
    "mutilQueue":2,
    "network":"10.0.0.2/24"
}

~~~

# System Variables

For ICMP server, we need set `net.ipv4.icmp_echo_ignore_all=1`.

for QUIC server and client, we need set `net.core.rmem_max=2500000`.
