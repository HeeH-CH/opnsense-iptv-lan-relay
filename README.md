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

## 설치 전 확인

이 도구는 셋톱박스가 현재 일반 LAN에 연결되어 있는 경우를 전제로 합니다. 먼저 OPNsense 콘솔이나 SSH에서 다음 정보를 확인합니다.

1. WAN과 LAN 인터페이스 이름:

```sh
ifconfig -l
```

2. 셋톱박스 MAC 주소:
   - OPNsense 웹 UI의 DHCP 임대 목록 또는 ARP 목록에서 확인합니다.
   - 셋톱박스를 재부팅한 뒤 새로 나타나는 DHCP 임대를 확인하면 찾기 쉽습니다.

MAC 주소는 `aa:bb:cc:dd:ee:ff` 형식이어야 합니다. 실제 MAC 주소와 내부 IP 정보는 공개 저장소나 이슈에 올리지 마세요.

## 설치

```sh
install -d -m 700 /conf/iptv-relay
install -m 700 iptv-relay.py /conf/iptv-relay/iptv-relay.py
install -m 755 iptv-relay.rc /usr/local/etc/rc.d/iptv-relay
install -d -m 755 /etc/rc.conf.d
cp iptv-relay.conf.example /etc/rc.conf.d/iptv-relay
chmod 600 /etc/rc.conf.d/iptv-relay
```

`/etc/rc.conf.d/iptv-relay`을 열어 실제 인터페이스 이름과 셋톱박스 MAC 주소를 설정합니다.

```sh
iptv_relay_enable="YES"
iptv_relay_args="--wan <WAN_인터페이스> --lan <LAN_인터페이스> --stb-mac <셋톱_MAC>"
```

예를 들어 인터페이스 이름은 `igb0`, `igb1`처럼 시스템마다 다릅니다. 예시의 값은 반드시 실제 환경에 맞게 바꿔야 합니다.

## 첫 실행

처음에는 백그라운드 서비스 대신 foreground로 실행해 로그를 직접 확인하는 편이 좋습니다.

```sh
python3 /conf/iptv-relay/iptv-relay.py \
  --wan <WAN_인터페이스> \
  --lan <LAN_인터페이스> \
  --stb-mac <셋톱_MAC>
```

셋톱박스에서 채널을 전환했을 때 `join 233.x.x.x`가 보이면 IGMP 감지는 정상입니다. `Ctrl+C`로 종료한 뒤 서비스로 실행합니다.

```sh
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

셋톱박스가 leave 직후 같은 group에 다시 join하는 환경에서는 기본 5초 leave 유예가 짧은 stream 중단을 줄입니다. 필요하면 `iptv_relay_args`에 `--leave-grace 8`처럼 초 단위 값을 추가할 수 있습니다.

## 문제 해결

| 증상 | 우선 확인할 내용 |
| --- | --- |
| `join` 로그가 보이지 않음 | `--stb-mac`과 LAN 인터페이스 이름이 맞는지, 셋톱박스가 실제로 채널을 전환했는지 확인합니다. |
| `join`은 보이지만 `forwarded_packets=0` | WAN 인터페이스 이름과 upstream의 IGMP 허용 여부를 확인합니다. WAN에서 IGMP report가 나가는지 `tcpdump -ni <WAN_인터페이스> igmp`로 확인합니다. |
| 서비스가 시작되지 않음 | `service iptv-relay status`와 `tail -n 100 /var/log/iptv-relay.log`를 확인합니다. |
| 영상이 끊기거나 검은 화면 | 셋톱박스에서 채널을 다시 전환하고, LAN switch의 IGMP snooping 설정 및 multicast 차단 정책을 확인합니다. |

## 제한 사항

- IPv4 IGMPv2와 `233.0.0.0/8` multicast group만 처리합니다.
- OPNsense GUI 플러그인이 아니라 root 권한으로 동작하는 사용자 공간 relay입니다.
- 일반 LAN으로 multicast UDP를 재전송하므로, 네트워크 장비의 IGMP snooping 동작에 따라 다른 LAN 장비에도 multicast traffic이 보일 수 있습니다.

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
