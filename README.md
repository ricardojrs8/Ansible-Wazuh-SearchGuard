
# Ansible-Wazuh-SearchGuar

_ejecución de wazuh con ansible._




```
---
- hosts: localhost
  become: yes
  become_user: root
  roles:
   - ansible-wazuh-manager
   - ansible-filebeat
   - ansible-elasticsearch
   - ansible-kibana
   #- ansible-searchguar-elastic
   #- ansible-searchguar-kibana
   #- ansible-https-kibana

```

_ verificar la sintaxi_
```
ansible-playbook --syntax-check wazuh-autom.yml
```
_ejecución_

```
time ansible-playbook -i ./gce.py wazuh-autom.yml
```

```
---
- hosts: localhost
  become: yes
  become_user: root
  roles:
   #- ansible-wazuh-manager
   #- ansible-filebeat
   #- ansible-elasticsearch
   #- ansible-kibana
   - ansible-searchguar-elastic
   #- ansible-searchguar-kibana
   #- ansible-https-kibana

```

_En nuestro caso utilizaremos las últimas versiones, para evitar confusiones.
Nos vamos hacia_

```
# cd /usr/share/elasticsearch

```

```
# sudo bin/elasticsearch-plugin install https://maven.search-guard.com/search-guard-suite-release/com/floragunn/search-guard-suite-plugin/7.9.2-46.2.0/search-guard-suite-plugin-7.9.2-46.2.0.zip
```

_ verificar la sintaxi_
```
ansible-playbook --syntax-check wazuh-autom.yml
```
_ejecución_

```
time ansible-playbook -i ./gce.py wazuh-autom.yml
```

```
---
- hosts: localhost
  become: yes
  gather_facts: no
  connection: local
  roles:
   #- ansible-wazuh-manager
   #- ansible-filebeat
   #- ansible-elasticsearch
   #- ansible-kibana
   #- ansible-searchguar-elastic
   - ansible-searchguar-kibana
   #- ansible-https-kibana
```

```
# cd /usr/share/kibana/

```

```
# sudo -u kibana bin/kibana-plugin install https://maven.search-guard.com/search-guard-kibana-plugin-release/com/floragunn/search-guard-kibana-plugin/7.9.2-46.2.0/search-guard-kibana-plugin-7.9.2-46.2.0.zip
```


## Seguridad de wazuh api

```
# ansible-playbook --syntax-check ca_wazuhp.yml

```

```
# time ansible-playbook -i ./gce.py ca_wazuhp.yml

```

_luego_

```
# cd /var/ossec/api/configuration/auth

```

```
# node htpasswd -Bc -C 10 user rickAmorA

```

_verificamos o cambiamos el usuario al nombre y contraseña que acabamos de generar_

```
nano /usr/share/kibana/optimize/wazuh/config/wazuh.yml

```

```

systemctl restart wazuh-manager
systemctl restart wazuh-api

```

## Seguridad de Kibana https

```
---
- hosts: localhost
  become: yes
  gather_facts: no
  connection: local
  roles:
   #- ansible-wazuh-manager
   #- ansible-filebeat
   #- ansible-elasticsearch
   #- ansible-kibana
   #- ansible-searchguar-elastic
   #- ansible-searchguar-kibana
   - ansible-https-kibana

```

_ejecutamos_

```
cat > /etc/nginx/sites-available/default <<\EOF
server {
    listen 80;
    listen [::]:80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 default_server;
    listen            [::]:443;
    ssl on;
    ssl_certificate /etc/ssl/certs/kibana-access.pem;
    ssl_certificate_key /etc/ssl/private/kibana-access.key;
    access_log            /var/log/nginx/nginx.access.log;
    error_log            /var/log/nginx/nginx.error.log;
    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;
        proxy_pass http://localhost:5601/;
    }
}
EOF

```

_ verificar la sintaxi_
```
ansible-playbook --syntax-check wazuh-autom.yml
```
_ejecución_

```
time ansible-playbook -i ./gce.py wazuh-autom.yml
```
