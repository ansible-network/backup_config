# (c) 2018, Ansible Inc,
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import copy
import os
import time
import re
import hashlib
import shutil
import md5
import q

from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.connection import Connection
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.module_utils.six.moves.urllib.parse import urlsplit
from ansible.utils.path import unfrackpath

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

ROLLBACK_DB_FILENAME = '.ansible_config_backup.txt'

class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        changed = False
        backupfile = None
        socket_path = None
        play_context = copy.deepcopy(self._play_context)

        result = super(ActionModule, self).run(task_vars=task_vars)


        if play_context.connection != 'network_cli':
            # It is supported only with network_cli
            result['failed'] = True
            result['msg'] = ('please use network_cli connection type for this'
                    'role')
            return result

        try:
            path = self._task.args.get('path')
        except KeyError as exc:
            return {'failed': True, 'msg': 'missing required argument: %s' % exc}

        try:
            filename = self._task.args.get('filename')
        except KeyError as exc:
            return {'failed': True, 'msg': 'missing required argument: %s' % exc}

        extensions = self._task.args.get('extensions')

        backup_dict = extensions.get('backup')
        backup_path = backup_dict.get('path')
        backup_path = unfrackpath(backup_path)

        if backup_dict:
            backup = True
            rollback_id_str = task_vars.get('ROLLBACK_ID_STR')
            if rollback_id_str is None:
                return {'failed': True, 'msg': 'VAR to write backup is not defined'}
        else:
            backup = False
       
        config_filters = None
        config_encrypt = None
        filters_ext = extensions.get('filters')
        if filters_ext:
            config_filters = filters_ext.get("lines")
            config_encrypt = filters_ext.get("encrypt")

        path = to_bytes(path, errors='surrogate_or_strict')
        path = unfrackpath(path)
        if not os.path.exists(path):
            return {'failed': True, 'msg': 'path: %s does not exist.' % path}
        filename = to_bytes(filename, errors='surrogate_or_strict')
        dest = os.path.join(path, filename)

        if socket_path is None:
            socket_path = self._connection.socket_path

        conn = Connection(socket_path)

        try:
            out = self._get_running_config(conn)
        except Exception as exc:
            result['failed'] = True
            result['msg'] = ('Exception received : %s' % exc)

        filter_encrypt_config = out
        if config_filters:
           # Filter configs and encrypt before writing to backup path
           try:
               filter_encrypt_config = self._handle_filters(out, config_filters,
                                                            config_encrypt)
           except ValueError as exc:
               result['failed'] = True
               result['msg'] = ('Exception received during encrypt: %s' % exc)

        try:
            changed, backupfile, r_id = self._write_backup(dest, filter_encrypt_config,
                                                          backup_path, filename,
                                                          rollback_id_str)
        except IOError as exc:
            result['failed'] = True
            result['msg'] = ('Exception received : %s' % exc)
            return result

        result['changed'] = changed
        if changed:
            result['destination'] = dest
        else:
            result['dest_unchanged'] = dest

        if backupfile:
            result['backup_file'] = backupfile
            result['rollback_seq'] = r_id

        return result

    def _get_running_config(self, connection):
        return connection.get_config(flags=[])

    def _write_backup(self, dest, contents, backup_path=None,
                      backup_filename=None, r_id=None):
        backupfile = None
        # Check for Idempotency
        if os.path.exists(dest):
            try:
                with open(dest, 'r') as f:
                    old_content = f.read()
            except IOError as ioexc:
                raise IOError(ioexc)
            sha1 = hashlib.sha1()
            old_content_b = to_bytes(old_content, errors='surrogate_or_strict')
            sha1.update(old_content_b)
            checksum_old = sha1.digest()

            sha1 = hashlib.sha1()
            new_content_b = to_bytes(contents, errors='surrogate_or_strict')
            sha1.update(new_content_b)
            checksum_new = sha1.digest()
            if checksum_old == checksum_new:
               return (False, backupfile, r_id)
            else:
               if backup_path:
                   backupfile, r_id  = self._create_backup(dest, backup_path,
                                                           backup_filename, r_id)

        try:
            with open(dest, 'w') as f:
                f.write(contents)
        except IOError as ioexc:
            raise IOError(ioexc)

        return (True, backupfile, r_id)

    def _create_backup(self, dest, backup_path, backup_filename, r_id):
        rollback_db_dest = os.path.join(backup_path, ROLLBACK_DB_FILENAME)
        if os.path.exists(rollback_db_dest):
            with open(rollback_db_dest, 'r') as f:
                current_rollback_seq = f.read()
                if current_rollback_seq:
                    current_rollback_seq = to_text(
                        current_rollback_seq,
                        errors='surrogate_or_strict'
                    )
                    current_rollback_seq = int(current_rollback_seq)
                else:
                    current_rollback_seq = 0
        else:
            current_rollback_seq = 0
           
        new_rollback_seq = current_rollback_seq + 1
        backup_dest = os.path.join(backup_path, backup_filename)
        q (r_id , new_rollback_seq, r_id % new_rollback_seq)
        rollback_id = r_id % new_rollback_seq
        q(rollback_id)
        backupdest = '%s.%s' %(backup_dest, rollback_id)
        shutil.copy2(dest, backupdest)
        
        # Increment rollback seq number
        with open(rollback_db_dest, 'w') as f:
            f.write(str(new_rollback_seq))

        return backupdest, new_rollback_seq

    def _handle_filters(self, out, filters, config_encrypt=None):
        filtered_configs_index = []
        filtered_configs = []
        configs = to_bytes(out, errors='surrogate_or_strict')
        conf_lines = configs.split('\n')
        for conf_filter in filters:
            r = re.compile(conf_filter)
            for index, line in enumerate(conf_lines):
                match_ob = r.match(line)
                if match_ob:
                    filtered_configs_index.append(index)
                    filtered_configs.append(line)

        for index in sorted(filtered_configs_index, reverse=True):
            del(conf_lines[index])

        if config_encrypt:
            key = config_encrypt.get("key")
            if key is None:
               raise ValueError("Encrypt key is reqiured when encrypt is set")
            encryption_key = self._get_key_from_password(key)
            encrypt_lines = self._encrypt_configs(filtered_configs,
                                                  encryption_key)
            n = len(encrypt_lines)
            for index in sorted(filtered_configs_index, reverse=True):
                conf_lines[index] = 'ansible_encrypted:::' + encrypt_lines[n-1]
                n = n -1

        filtered_config = '\n'.join(conf_lines)
        return filtered_config

    def _get_key_from_password(self, password):
        key =  md5.new(password).digest()
        return key

    def _encrypt_configs(self, filtered_configs, key):
        en_configs = []
        for config in filtered_configs:
            enc = self._encrypt_line(config, key)
            en_configs.append(enc)
        return en_configs

    def _encrypt_line(self, clear_text, key):
        from Crypto import Random
        from Crypto.Cipher import AES
        import base64

        self.bs = 32
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        clear_padded = self._pad(clear_text)
        return base64.b64encode(iv + cipher.encrypt(clear_padded))

    def _pad(self, s):
        return s + (self.bs - (len(s) % self.bs)) * chr(self.bs - (len(s) %
                    self.bs))
