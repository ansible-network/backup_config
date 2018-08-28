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


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
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

        path = to_bytes(path, errors='surrogate_or_strict')
        path = unfrackpath(path)

        filename = self._task.args.get('filename')

        config_decrypt = None
        seq_backup = None
        ext = self._task.args.get('extensions')
        q(ext)
        if ext:
            filters_ext = ext.get('filters')
            if filters_ext:
                config_decrypt = filters_ext.get("decrypt")
            seq_backup = ext.get('sequence')

        if not filename and not seq_backup:
            return {'failed': True, 'msg': 'filename or sequence is required:'}

        if not filename:
            rollback_id_str = task_vars.get('ROLLBACK_ID_STR')
            if rollback_id_str is None:
                return {'failed': True, 'msg': 'String to identify rollback is not defined'}
            # Look for backup file in path by sequence number specified
            try:
                filename = self._get_backup_filename(path, seq_backup, rollback_id_str)
            except ValueError as vexc:
                return {'failed': True, 'msg': 'could not find backup seq %d in '
                        'path %s' % (seq_backup, path)}

        if not os.path.exists(path):
            return {'failed': True, 'msg': 'path: %s does not exist.' % path}
        filename = to_bytes(filename, errors='surrogate_or_strict')
        dest = os.path.join(path, filename)

        with open(dest, 'r') as f:
            en_config = f.read()

        if socket_path is None:
            socket_path = self._connection.socket_path

        conn = Connection(socket_path)

        if config_decrypt:
           encrypt_filters = 'ansible_encrypted:::'
           #  Decrypt encrypted configs before writing to device
           try:
               text_config = self._handle_encryption(en_config, encrypt_filters,
                                                     config_decrypt)
           except ValueError as exc:
               result['failed'] = True
               result['msg'] = ('Exception received during encrypt: %s' % exc)
        else:
           text_config = en_config

        result = self._rollback_text_config(conn, text_config)

        return result

    def _handle_encryption(self, en_configs, filters, config_decrypt=None):
        filtered_configs_index = []
        filtered_configs = []
        configs = to_bytes(en_configs, errors='surrogate_or_strict')
        conf_lines = configs.split('\n')
        r = re.compile(filters)
        for index, line in enumerate(conf_lines):
            match_ob = r.match(line)
            if match_ob:
                filtered_configs_index.append(index)
                filtered_configs.append(line)

        for index in sorted(filtered_configs_index, reverse=True):
            del(conf_lines[index])

        if config_decrypt:
            key = config_decrypt.get("key")
            q(key)
            if key is None:
               raise ValueError("Decrypt key is reqiured for rollback config to device")
            decryption_key = self._get_key_from_password(key)
            clear = self._decrypt_configs(filtered_configs, decryption_key, filters)

            n = len(clear)
            for index in sorted(filtered_configs_index, reverse=True):
                conf_lines[index] = clear[n-1]
                n = n -1

        filtered_config = '\n'.join(conf_lines)
        return filtered_config

    def _get_key_from_password(self, password):
        key =  md5.new(password).digest()
        return key

    def _decrypt_configs(self, en_configs, key, filter_prefix):
        de_configs = []
        for en_line in en_configs:
            en_line = en_line[len(filter_prefix):]
            dec = self._decrypt_line(en_line, key)
            de_configs.append(dec)
        return de_configs

    def _decrypt_line(self, enc, key):
        from Crypto import Random
        from Crypto.Cipher import AES
        import base64

        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        clear_line = to_bytes(
                self._unpad(cipher.decrypt(enc[AES.block_size:])),
                errors='surrogate_or_strict'
        )
        return clear_line

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    def _rollback_text_config(self, connection, candidate):
        result = {}
        running = connection.get_config(flags=[])
        kwargs = {'candidate': candidate, 'running': running}
        diff_response = connection.get_diff(**kwargs)
        config_diff = diff_response.get('config_diff')
        banner_diff = diff_response.get('banner_diff')

        if config_diff:
            if isinstance(config_diff, list):
                candidate = config_diff
            else:
                candidate = config_diff.splitlines()

            kwargs = {'candidate': candidate}
            connection.edit_config(**kwargs)
            result['changed'] = True

        if banner_diff:
            candidate = json.dumps(banner_diff)

            kwargs = {'candidate': candidate, 'commit': commit}
            if multiline_delimiter:
                kwargs.update({'multiline_delimiter': multiline_delimiter})
            connection.edit_banner(**kwargs)
            result['changed'] = True

        diff = None
        if config_diff:
            if isinstance(config_diff, list):
                diff = '\n'.join(config_diff)
            else:
                diff = config_diff
        if banner_diff:
            diff += json.dumps(banner_diff)

        if diff:
            result['diff'] = {'prepared': diff}

        return result

    def _get_backup_filename(self, path, seq_backup, rollback_id_str):
        if not os.path.exists(path):
            raise ValueError("path : %s does not exist" % path)

        match_backup_name = rollback_id_str % seq_backup
        q(match_backup_name)
        for files in os.listdir(path):
            pos = files.find(match_backup_name)
            if pos >= 0:
                return files

        return None
