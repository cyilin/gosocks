gosocks
=======

A Golang implementation of socks5 proxy

##### Build

```
go get github.com/cyilin/gosocks
cd $GOPATH/src/github.com/cyilin/gosocks/socks5server
go install
```

##### Usage

```
#IPv4
socks5server -4 -listen="[::]:1090" -interface="本地连接 2" -dns="114.114.114.114"
#IPv6
socks5server -6 -listen="[::]:1095" -interface="本地连接 2" -dns="[2001:4860:4860::8844]"
#TCP DNS
socks5server -4 -listen="[::]:1091" -interface="本地连接 3" -dns="tcp://8.8.8.8:53"
```

##### Thanks

* [yinghuocho/gosocks](https://github.com/yinghuocho/gosocks)

* [miekg/dns](https://github.com/miekg/dns)