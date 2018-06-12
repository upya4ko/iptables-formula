{%- from "iptables/map.jinja" import map with context -%}

{% if map.install %}
install_iptables:
  pkg.installed:
    - pkgs: {{ map.pkgs }}
{% else %}
remove_iptabless:
  pkg.purged:
    - pkgs: {{ map.pkgs }}
{% endif %}
