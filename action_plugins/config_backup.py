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

from ansible.module_utils._text import to_bytes
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
        play_context.network_os = self._get_network_os(task_vars)

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

        try:
            command = self._task.args.get('command')
        except KeyError as exc:
            return {'failed': True, 'msg': 'missing required argument: %s' % exc}

        backup_str = self._task.args.get('backup')
     
        if backup_str == 'yes':
            backup = True
        else:
            backup = False

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
            out = conn.send_command(command)
        except Exception as exc:
            result['failed'] = True
            result['msg'] = ('Exception received : %s' % exc)

        try:
            changed, backupfile = self._write_backup(dest, out, backup)
        except IOError as exc:
            result['failed'] = True
            result['msg'] = ('Exception received : %s' % exc)
   
        result['changed'] = changed
        if changed:
            result['destination'] = dest
        else:
            result['dest_unchanged'] = dest
        
        if backupfile:
            result['backup_file'] = backupfile

        return result

    def _write_backup(self, dest, contents, backup):
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
               return (False, backupfile)
            else:
               if backup:
                   backupfile = self._create_backup(dest)

        try:
            with open(dest, 'w') as f:
                f.write(contents)
        except IOError as ioexc:
            raise IOError(ioexc)

        return (True, backupfile)

    def _create_backup(self, dest):
        ext = time.strftime("%Y-%m-%d@%H:%M:%S~", time.localtime(time.time()))
        backupdest = '%s.%s' %(dest, ext)
        shutil.copy2(dest, backupdest)
        return backupdest

    def _get_network_os(self, task_vars):
        if 'network_os' in self._task.args and self._task.args['network_os']:
            display.vvvv('Getting network OS from task argument')
            network_os = self._task.args['network_os']
        elif self._play_context.network_os:
            display.vvvv('Getting network OS from inventory')
            network_os = self._play_context.network_os
        elif 'network_os' in task_vars.get('ansible_facts', {}) and task_vars['ansible_facts']['network_os']:
            display.vvvv('Getting network OS from fact')
            network_os = task_vars['ansible_facts']['network_os']
        else:
            raise AnsibleError('ansible_network_os must be specified on this host to use platform agnostic modules')

        return network_os
