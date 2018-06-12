{%- from "iptables/map.jinja" import map with context -%}

include:
  - iptables.install

{# --------- flush iptables before add new --------- #}
flush_iptables_rules:
  iptables.flush:
    - table: filter
    - family: ipv4
flush_iptables_rules2:
  iptables.flush:
    - table: filter
    - family: ipv6
    - require_in:
      - iptables: flush_iptables_rules
flush_iptables_rules3:
  iptables.flush:
    - table: nat
    - family: ipv4
    - require_in:
      - iptables: flush_iptables_rules2
flush_iptables_rules4:
  iptables.flush:
    - table: nat
    - family: ipv6
    - require_in:
      - iptables: flush_iptables_rules3
flush_iptables_rules5:
  iptables.flush:
    - table: mangle
    - family: ipv4
    - require_in:
      - iptables: flush_iptables_rules4
flush_iptables_rules6:
  iptables.flush:
    - table: mangle
    - family: ipv6
    - require_in:
      - iptables: flush_iptables_rules5
flush_iptables_rules7:
  iptables.flush:
    - table: raw
    - family: ipv4
    - require_in:
      - iptables: flush_iptables_rules6
flush_iptables_rules8:
  iptables.flush:
    - table: raw
    - family: ipv6
    - require_in:
      - iptables: flush_iptables_rules7
flush_iptables_rules9:
  iptables.flush:
    - table: security
    - family: ipv4
    - require_in:
      - iptables: flush_iptables_rules8
flush_iptables_rules10:
  iptables.flush:
    - table: security
    - family: ipv6
    - require_in:
      - iptables: flush_iptables_rules9
{# --------- flush iptables before add new --------- #}

{% for rule in map.rules %}

{% set table = salt['pillar.get']('iptables:rules:'~rule~':table', 'filter') %}
{% set chain = salt['pillar.get']('iptables:rules:'~rule~':chain', 'INPUT') %}
{% set jump = salt['pillar.get']('iptables:rules:'~rule~':jump', 'ACCEPT') %}
{% set source = salt['pillar.get']('iptables:rules:'~rule~':source', False) %}
{% set dport = salt['pillar.get']('iptables:rules:'~rule~':dport', False) %}
{% set sport = salt['pillar.get']('iptables:rules:'~rule~':sport', False) %}
{% set protos = salt['pillar.get']('iptables:rules:'~rule~':protos', ['tcp']) %}
{% set save = salt['pillar.get']('iptables:rules:'~rule~':save', True) %}
{% set family = salt['pillar.get']('iptables:rules:'~rule~':family', 'ipv4') %}
{% set i_int = salt['pillar.get']('iptables:rules:'~rule~':i_int', False) %}
{% set o_int = salt['pillar.get']('iptables:rules:'~rule~':o_int', False) %}
{% set match = salt['pillar.get']('iptables:rules:'~rule~':match', False) %}
{% set ctstate = salt['pillar.get']('iptables:rules:'~rule~':ctstate', False) %}
{% set position = salt['pillar.get']('iptables:rules:'~rule~':position', False) %}
{% set insert = salt['pillar.get']('iptables:rules:'~rule~':insert', False) %}
{% set comment_pillar = salt['pillar.get']('iptables:rules:'~rule~':comment', False) %}
  {% if comment_pillar %}
    {% set comment = 'Rule_'~rule~': '~comment_pillar %}
  {% else %}
    {% set comment = 'Rule_'~rule %}
  {% endif %}

{% if salt['pillar.get']('iptables:rules:'~rule~':enabled', True) %}
# install rule

{% for proto in protos %}

create_iptables_rule_{{ rule }}_{{ proto }}:
  {% if insert %}
  iptables.insert:
  {% else %}
  iptables.append:
  {% endif %}
    - name: iptables_{{ rule }}
    - table: {{ table }}
    - chain: {{ chain }}
    - jump: {{ jump }}
    {% if position %}
    - position: {{ position }}
    {% endif %}
    {% if source %}
    - source: {{ source }}
    {% endif %}
    {% if dport %}
    - dport: {{ dport }}
    {% endif %}
    {% if sport %}
    - sport: {{ sport }}
    {% endif %}
    {% if not insert %}
    - proto: {{ proto }}
    {% endif %}
    - family: {{ family }}
    {% if i_int %}
    - in-interface: {{ i_int }}
    {% endif %}
    {% if o_int %}
    - out-interface: {{ o_int }}
    {% endif %}
    {% if match %}
    - match: {{ match }}
    {% endif %}
    {% if ctstate %}
    - ctstate: {{ ctstate }}
    {% endif %}
    {% if comment %}
    - comment: "{{ comment }} {% if not insert %}{{ proto }}{% endif %}"
    {% endif %}
    - save: {{ save }}
    - require: 
      - pkg:  install_iptables
      - iptables: flush_iptables_rules

{% endfor %}

{% else %}
{# --------- Clean rules file --------- #}
clean_rules_{{ rule }}:
  cmd.run:
    {% if family == 'ipv4' %}
    - name: 'grep -v "{{ comment }}" /etc/iptables/rules.v4 > /tmp/ipv4.tmp && mv /tmp/ipv4.tmp /etc/iptables/rules.v4'
    {% elif family == 'ipv6' %}
    - name: 'grep -v "{{ comment }}" /etc/iptables/rules.v6 > /tmp/ipv6.tmp && mv /tmp/ipv6.tmp /etc/iptables/rules.v6'
    {% endif %}
    - require:
      - iptables: flush_iptables_rules
  
{% endif %}
{% endfor %}
