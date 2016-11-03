# Logstash-JunOS-Grok
Grok statements for JunOS(SRX Series) log events

Note: log format may depend on what version of JunOS you are running

#########################################################
RT Flow Session Close

Log format:
session closedreason: source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 packets-from-client(bytes-from-client) packets-from-server(bytes-from-server) elapsed-time application nested-application username(roles) packet-incoming-interface encrypted

Grok:
<%{POSINT}>%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA}(?:\[%{POSINT}\])?: %{DATA:apptrack_status}: %{DATA:reason_message}: %{IP:source_ip}\/%{NUMBER:source_port}->%{IP:dest_ip}\/%{NUMBER:dest_port} %{DATA:service_name} %{IP:nat_source_ip}\/%{NUMBER:nat_source_port}->%{IP:nat_dest_ip}\/%{NUMBER:nat_dest_port} %{DATA:source_nat_rule_name} %{DATA:dest_nat_rule_name} %{NUMBER:protocol_id} %{DATA:policy_name} %{DATA:source_zone} %{DATA:dest_zone} %{NUMBER:session_id} %{DATA:packets_from_client} %{DATA:packets_from_server} %{NUMBER:elapsed_time} %{DATA:application} %{DATA:nested_application} %{DATA:username} %{DATA:packet_incoming_interface} %{DATA:encryption}

RT Flow Session Create

Log format:
session created source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 username(roles) packet-incoming-interface 

Grok:
<%{POSINT}>%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA}(?:\[%{POSINT}\])?: %{DATA:apptrack_status}: %{DATA:reason_message} %{IP:source_ip}\/%{NUMBER:source_port}->%{IP:dest_ip}\/%{NUMBER:dest_port} %{DATA:service_name} %{IP:nat_source_ip}\/%{NUMBER:nat_source_port}->%{IP:nat_dest_ip}\/%{NUMBER:nat_dest_port} %{DATA:src_nat_rule_name} %{DATA:dest_nat_rule_name} %{NUMBER:protocol_id} %{DATA:policy_name} %{DATA:source_zone} %{DATA:dest_zone} %{NUMBER:session_id} %{DATA:username} %{DATA:packet_incoming_interface} %{DATA}

#########################################################
AppTrack Session Close

Log format:
AppTrack session created source-address/source-port->destination-address/destination-port service-name application nested-application nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 username roles encrypted

Grok:
<%{POSINT}>%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA}(?:\[%{POSINT}\])?: %{DATA:apptrack_status}: %{DATA:reason_message}: %{IP:source_ip}\/%{NUMBER:source_port}->%{IP:dest_ip}\/%{NUMBER:dest_port} %{DATA:service_name} %{DATA:application} %{DATA:nested_application} %{IP:nat_source_ip}\/%{NUMBER:nat_source_port}->%{IP:nat_dest_ip}\/%{NUMBER:nat_dest_port} %{DATA:src_nat_rule_name} %{DATA:dst_nat_rule_name} %{NUMBER:protocol_id} %{DATA:policy_name} %{DATA:source_zone} %{DATA:dest_zone} %{NUMBER:session_id} %{DATA:packets_from_client} %{DATA:packets_from_server} %{NUMBER:elapsed_time} %{DATA:username} %{DATA:roles} %{DATA:encrypted}\s

AppTrack Session Create

Log format:
AppTrack session created source-address/source-port->destination-address/destination-port service-name application nested-application nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 username roles encrypted 

Grok:
<%{POSINT}>%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA}: %{DATA:apptrack_status}: %{DATA:reason_message} %{IP:source_ip}\/%{NUMBER:source_port}->%{IP:dest_ip}\/%{NUMBER:dest_port} %{DATA:service_name} %{DATA:application} %{DATA:nested_application} %{IP:nat_source_ip}\/%{NUMBER:nat_source_port}->%{IP:nat_dest_ip}\/%{NUMBER:nat_dest_port} %{DATA:source_nat_rule_name} %{DATA:dest_nat_rule_name} %{NUMBER:protocol_id} %{DATA:policy_name} %{DATA:source_zone} %{DATA:dest_zone} %{NUMBER:session_id} %{DATA:username} %{DATA:roles} %{DATA:encrypted}\s

AppTrack Session Vol Update

Log format:
AppTrack volume update: source-address/source-port->destination-address/destination-port service-name application nested-application nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 packets-from-client(bytes-from-client) packets-from-server(bytes-from-server) elapsed-time username roles encrypted

Grok:
<%{POSINT}>%{SYSLOGTIMESTAMP} %{SYSLOGHOST} %{DATA}(?:\[%{POSINT}\])?: %{DATA:apptrack_status}: %{DATA:reason_message}: %{IP:source_ip}\/%{NUMBER:source_port}->%{IP:dest_ip}\/%{NUMBER:dest_port} %{DATA:service_name} %{DATA:application} %{DATA:nested_application} %{IP:nat_source_ip}\/%{NUMBER:nat_source_port}->%{IP:nat_dest_ip}\/%{NUMBER:nat_dest_port} %{DATA:src_nat_rule_name} %{DATA:dst_nat_rule_name} %{NUMBER:protocol_id} %{DATA:policy_name} %{DATA:source_zone} %{DATA:dest_zone} %{NUMBER:session_id} %{DATA:packets_from_client} %{DATA:packets_from_server} %{NUMBER:elapsed_time} %{DATA:username} %{DATA:roles} %{DATA:encrypted}\s
