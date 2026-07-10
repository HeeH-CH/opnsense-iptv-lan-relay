# OPNsense IPTV LAN Relay

OPNsense/FreeBSD 환경에서 IGMP proxy가 셋톱박스의 IGMP report를 처리하지 못할 때 사용할 수 있는 LAN 유지형 IPTV multicast relay입니다.

셋톱박스를 기존 LAN에 둔 상태로 동작합니다. 별도 IPTV 포트나 WAN-LAN 브리지를 만들지 않습니다.

## 동작 방식

1. LAN에서 셋톱박스가 보내는 IGMPv2 join/leave를 `tcpdump`로 감지합니다.
2. WAN 인터페이스 주소를 소스로 하여 같은 join/leave를 upstream으로 전송합니다.
3. WAN에서 수신한 활성 multicast UDP stream을 LAN으로 재전송합니다.
4. 60초마다 LAN에 IGMP general query를 보내 active group을 갱신합니다.

이 방식은 OPNsense의 기본 IGMP 수신 경로를 우회하기 위해 BPF packet capture와 raw IP socket을 사용합니다.

## 주의

- 방화벽, 인터넷 회선, 셋톱박스마다 동작 방식이 다릅니다. 운영 환경에 적용하기 전에 콘솔 또는 별도 관리 경로를 확보하세요.
- 이 도구는 IGMPv2와 `233.0.0.0/8` multicast group을 대상으로 합니다.
- 실제 MAC 주소, 공인 IP, 내부 IP 대역, 설정 백업, 로그는 저장소에 넣지 마세요.
- 서비스 제공사의 약관과 네트워크 정책을 준수하세요.

## 요구 사항

- OPNsense 또는 FreeBSD
- Python 3
- `tcpdump`
- root 권한

## 설치

```sh
install -d -m 700 /conf/iptv-relay
install -m 700 iptv-relay.py /conf/iptv-relay/iptv-relay.py
install -m 755 iptv-relay.rc /usr/local/etc/rc.d/iptv-relay
install -d -m 755 /etc/rc.conf.d
cp iptv-relay.conf.example /etc/rc.conf.d/iptv-relay
```

`/etc/rc.conf.d/iptv-relay`에서 인터페이스 이름과 셋톱박스 MAC 주소를 실제 값으로 바꿉니다.

```sh
sysrc iptv_relay_enable=YES
service iptv-relay start
service iptv-relay status
tail -f /var/log/iptv-relay.log
```

## 확인 방법

셋톱박스에서 채널을 전환한 뒤 로그에 `join 233.x.x.x`가 보이는지 확인합니다.

```sh
tcpdump -ni <LAN_인터페이스> 'udp and dst net 233.0.0.0/8'
```

`forwarded_packets` 값이 주기적으로 증가하면 WAN multicast stream이 LAN으로 전달되고 있는 것입니다.

## 중지 및 제거

```sh
service iptv-relay stop
sysrc -x iptv_relay_enable
rm -f /usr/local/etc/rc.d/iptv-relay
rm -rf /conf/iptv-relay
rm -f /etc/rc.conf.d/iptv-relay
```

## 라이선스

MIT License
