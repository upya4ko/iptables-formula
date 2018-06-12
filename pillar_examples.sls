iptables:
  rules:
    example_rules:
      table: filter # filter | nat | mangle | raw | security
      chain: INPUT  # INPUT | OUTPUT
      source: 10.20.0.0/24 # name | hostname | network IP (with /mask) | plain IP address
      dport: 80
      sport: 1025:65535
      protos: 
        - tcp    # tcp, udp, udplite, icmp, icmpv6,esp, ah, sctp, mh, all
        - udp
      family: ipv4  # ipv4 | ipv6
      comment: "Allow HTTP"
      save: True

    openvpn_1:
      insert: True
      position: 1
      jump: ACCEPT
      chain: FORWARD
      i_int: tun0
      o_int: eth0
      source: '10.9.8.0/24'
      match: conntrack
      ctstate: NEW

    openvpn_2:
      insert: True
      position: 1
      jump: ACCEPT
      chain: FORWARD
      match: conntrack
      ctstate: 'RELATED,ESTABLISHED'

    openvpn_3:
      insert: True
      position: 1
      jump: MASQUERADE
      chain: POSTROUTING
      source: '10.9.8.0/24'
      o_int: eth0
      table: nat

    ssh:
      enabled: True
      table: filter
      dport: 22
      jump: ACCEPT
      chain: INPUT
      protos: 
        - tcp

    http:
      enabled: True
      dport: 80
      jump: ACCEPT
      protos: 
        - tcp
        - udp
      comment: "webserver rule"

