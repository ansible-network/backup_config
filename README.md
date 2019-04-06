backup_config
=========

Role to collects the current device configurations and store it on the Ansible
controller with a user specific backup filename and path. It copies running-config
from remote device via SSH so it works only with network_cli connections.
More info about using network_cli connection to connect to network device can be
found at https://docs.ansible.com/ansible/2.5/network/index.html#network-guide

Features
--------

- Role supports idempotent behaviour so if there is no difference between current configurations
and configurations present in destination file then it will return changed=0 and will not overwrite
destination filename. 

- If there is a change detected between current configurations and configurations present in 
destination file, it can backup last configurations before overwriting to new config file. 

- By using above features, one can run this role periodically with backup option as "yes" to 
create devices configurations change history on local disk of ansible controller.

Requirements
------------

- Ansible 2.5 or later

Role Variables
--------------

- filename: filename to store configurations
- path: Absolute of relative path of folder where config will be stored
- backup: boolean flag to indicate if we need to backup configurations before
overwriting it with new configurations

Dependencies
------------
- None

Example Playbook
----------------

```
---
- hosts: iosxr01 csr01
  roles:
    - backup_config
  vars:
        {
          "backup_config": {
            "filename" : "config_{{ ansible_host }}.cfg",
            "path" : "~/network_configs_1/",
            "backup" : "yes"
          }
        }

```
License
-------

Apache

Author Information
------------------

Ansible-Networking-Team
