#!/usr/local/bin/python3.4

'''
    Copyright 2017 Manos Pitsidianakis
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import subprocess
import json
import re
import argparse
from pathlib import Path
from os.path import expanduser
from os import getuid
from pwd import getpwuid

conf_file = expanduser('~/wicc.conf')
if Path(conf_file).is_file() is False:
    conf = {}
    conf['if'] = ''
    conf['networks'] = {
            'network name': {
                'autoconnect' : True,
                'nwid' : 'network nwid',
                'wpakey' : 'passphrase',
                'vpn'   :   True,
                'wpa_supplicant'    :   False
                },
            'network name 2 ' : {
                'nwid'  :   'network nwid 2',
                'dhclient.conf' :   False
                }
        }
    conf['vpn'] = {
            'anchor' : 'vpn',
            'anchor-file' : '/etc/pf.anchors/vpn.conf',
            'ovpn' : '~/openvpn/vpn.ovpn',
            'chroot'    :   '~/openvpn',
            'dir'   :   '~/openvpn'
            }
    conf['dhclient.conf'] = ''
    conf['ifconfig'] = 'ifconfig'
    conf['doas'] = 'doas'
    conf['wpa_supplicant'] = '/etc/wpa_supplicant.conf'
    with open(conf_file, 'w') as data_file:
            json.dump(conf,data_file,indent='\t',sort_keys=True)
    print('Example config generated at '+conf_file)
    print('Add the following on /etc/doas.conf if you wish to use doas with non-root user:')
    user = getpwuid( getuid() )[ 0 ]
    print('''
    permit nopass '''+user+''' as root cmd ifconfig
    permit nopass '''+user+''' as root cmd dhclient
    permit nopass '''+user+''' as root cmd wpa_supplicant
    permit nopass '''+user+''' as root cmd openvpn
    permit nopass '''+user+''' as root cmd pfctl args -a vpn -F rules
    permit nopass '''+user+''' as root cmd pfctl args -a vpn -f PF_VPN_ANCHOR_FILE #replace
    permit nopass '''+user+''' as root cmd pkill args INT wpa_supplicant
    permit nopass '''+user+''' as root cmd pkill args INT openvpn''')
    exit(0)

with open(conf_file, 'r') as data_file:
    conf = json.load(data_file)
interface = conf['if']


'''
'' Set doas=None if you run as root.
'''
doas = conf['doas']
ifconfig = conf['ifconfig']

avail_ap = {}

def reduce(f, l):
    v = None
    for i in l:
        if v is None:
            v = i
        else:
            v = f(v,i)
    return v

def print_nwid(s):
    try:
        if s.startswith('0x'):
            int(s[2:],16)
            s = bytes.fromhex(s[2:]).decode('utf-8')
    except ValueError as e:
        pass
    return s

def scan():
    network_r = re.compile('^\s*nwid\s"?([^"]+)"?\schan\s(\d+)\sbssid\s((?:[\w]{2}\:){5}[\w]{2})\s(.+)dBm\s(.+)')
    command = [ifconfig, interface, 'scan']
    if doas:
        command.insert(0,doas)
    for line in subprocess.check_output(command, universal_newlines=True).splitlines():
        if network_r.match(line):
            m = network_r.match(line)
            name = m.group(1)
            chan = m.group(2)
            bssid= m.group(3)
            strength = m.group(4)
            options = m.group(5)
            if name not in avail_ap:
                avail_ap[name] = []
            avail_ap[name].append({ 'chan': chan, 'bssid' : bssid, 'strength': strength, 'options': options })


def run_command(command):
    if doas:
        command.insert(0,doas)
    if args.verbose:
        print(reduce( lambda a,b: a+' '+b, command))
    try:
        output = subprocess.check_output(command)
        if args.verbose and len(output) >0:
            print(output)
    except subprocess.CalledProcessError as e:
        print(e.returncode, e.output)
        exit(1)

def openvpn(connect=False,disconnect=False,anchor_enable=False,anchor_disable=False):
    if 'vpn' not in conf or conf['vpn'] is None:
        return

    if anchor_enable:
        if args.verbose:
            print('Enabling vpn anchor for pf')
        if 'anchor' in conf['vpn']:
            command = ['pfctl', '-a', conf['vpn']['anchor'], '-f' ,conf['vpn']['anchor-file']]
            run_command(command)

    if anchor_disable:
        if args.verbose:
            print('Disabling vpn anchor for pf')
        if 'vpn' in conf and conf['vpn'] and 'anchor' in conf['vpn']:
            command = ['pfctl', '-a', conf['vpn']['anchor'], '-F' ,'rules']
            run_command(command)

    if disconnect:
        if args.verbose:
            print('Killing openvpn daemon')
        command = ['pkill','INT', 'openvpn']
        if doas:
            command.insert(0,doas)
        try:
            output = subprocess.check_output(command)
            if args.verbose and len(output)>0:
                print(output)
        except subprocess.CalledProcessError as e:
            # Exit Status 1 means no process was matched
            if e.returncode > 1:
                print(e.output)
                print("pkill exited with "+e.returncode)
                exit(1)
    if connect:
        if args.verbose:
            print('Starting openvpn daemon')
        command = ['openvpn','--cd',conf['vpn']['cd'], '--daemon', '--config',conf['vpn']['ovpn']]
        run_command(command)

    return

def disconnect():
    openvpn(disconnect=True, anchor_disable=True)
    command = [ifconfig, interface,'-wpakey', '-wpa','-nwid','-bssid']
    if doas:
        command.insert(0,doas)
    subprocess.check_output(command)
    command = [ifconfig, interface,'down']
    if doas:
        command.insert(0,doas)
    subprocess.check_output(command)
    if args.verbose:
        print('Killing wpa_supplicant daemon')
    command = ['pkill','INT', 'wpa_supplicant']
    if doas:
        command.insert(0,doas)
    try:
        output = subprocess.check_output(command)
        if args.verbose and len(output)>0:
            print(output)
    except subprocess.CalledProcessError as e:
        # Exit Status 1 means no process was matched
        if e.returncode > 1:
            print(e.output)
            print("pkill exited with "+e.returncode)
            exit(1)

def status():
    status_r = re.compile('^\s*status: (\w+)')
    nwid_r = re.compile('^\s*\w+: nwid "?([^"]+)"? chan (\d+) bssid ((?:[\w]{2}\:){5}[\w]{2}) (.+)dBm')
    strength = None
    nwid = None
    status = None
    command = [ifconfig, interface]
    if doas:
        command.insert(0,doas)
    for line in subprocess.check_output(command, universal_newlines=True).splitlines():
        if status_r.match(line):
            status = status_r.match(line).group(1)
            continue
        if status and nwid_r.match(line):
            nwid = nwid_r.match(line).group(1)
            strength = nwid_r.match(line).group(4)
            break
    if args.verbose:
        print('Active: '+str(status)+' nwid='+print_nwid(str(nwid))+' strength='+str(strength))
    if status.strip() == 'active':
        return True
    else:
        return False

def connect(network=None, nwid=None, wpakey=None, auto=False,bssid=None):
    scan()
    options = None
    vpn = None
    if auto and nwid is None:
        curr_strength = -100
        # find all saved networks that are in range and set to autoconnect
        for n in conf['networks']:
            entry = conf['networks'][n]
            if entry['nwid'] in avail_ap and entry['autoconnect']:
                if curr_strength<int(avail_ap[entry['nwid']][0]['strength']):
                    curr_strength=int(avail_ap[entry['nwid']][0]['strength'])
                else:
                    continue
                nwid=entry['nwid']
                if 'vpn' in entry:
                    vpn = entry['vpn']
                else:
                    vpn = None
                if 'wpakey' in entry:
                    wpakey=entry['wpakey']
                else:
                    wpakey=None
        if nwid is None:
            if args.verbose:
                print('could not find any saved network in range')
            exit(1)
    if network in conf['networks'] and nwid is None and wpakey is None:
        if 'wpakey' in conf['networks'][network]:
            wpakey= conf['networks'][network]['wpakey']
        nwid = conf['networks'][network]['nwid']
        if 'vpn' in conf['networks'][network]:
            vpn = conf['networks'][network]['vpn']
    if network not in conf['networks'] and nwid is None:
        nwid=network
    if nwid is None:
        # at this point nwid must have a value
        if args.verbose:
            print('nwid=None!')
        exit(1)
    if nwid not in avail_ap:
        if args.verbose:
            print(avail_ap)
            print('could not find network in range with nwid '+nwid+', exiting.')
        exit(1)
    if args.verbose:
        print('Clearing interface settings...')
    disconnect()
    command = [ifconfig, interface,'up']
    if doas:
        command.insert(0,doas)
    subprocess.check_output(command)

    if args.verbose:
        print('Connecting to '+print_nwid(nwid))
    if vpn:
        openvpn(anchor_enable=True)
    command = ['ifconfig', interface]
    command.append('nwid')
    command.append(nwid)
    if wpakey:
        command.append('wpakey')
        command.append(wpakey)
    if len(avail_ap[nwid]) > 1 and bssid is None:
        # if we have more than one bssids, choose the one with the best signal
        avail_ap[nwid].sort(key=lambda ap: ap['strength'])
        bssid = avail_ap[nwid][0]['bssid']
    if nwid in conf['networks'] and 'bssid' in conf['networks'][nwid] and bssid is None:
        bssid = conf['networks'][nwid]['bssid']
    if bssid:
        command.append('bssid')
        command.append(bssid)
    if doas:
        command.insert(0,doas)
    if '802.1x' in avail_ap[nwid][0]['options']:
        command.append('wpa')
        command.append('wpaakms')
        command.append('802.1x')
    command.append('up')
    if args.verbose:
        print(reduce( lambda a,b: a+' '+b, command))
    output = subprocess.check_output(args=command, universal_newlines=True,stderr=subprocess.STDOUT).rstrip()
    if '802.1x' in avail_ap[nwid][0]['options']:
        if nwid in conf['networks'] and 'wpa_supplicant' in conf['networks'][nwid] and conf['networks'][nwid]['wpa_supplicant']:
            command = ['wpa_supplicant','-Bc',conf['wpa_supplicant'],'-D','openbsd','-i',interface,]
            if doas:
                command.insert(0,doas)
            if args.verbose:
                print(reduce( lambda a,b: a+' '+b, command))
            output = subprocess.check_output(args=command, universal_newlines=True).rstrip()
        else:
            if args.verbose:
                print('802.1x authentication required for '+print_nwid(nwid))
            exit(1)
    command = ['dhclient']
    if nwid in conf['networks'] and conf['dhclient.conf']:
        if 'dhclient.conf' not in conf['networks'][nwid] or conf['networks'][nwid]['dhclient.conf'] is True:
            command.append('-c')
            command.append(conf['dhclient.conf'])
        elif 'dhclient.conf' not in conf['networks'][nwid] or isinstance(conf['networks'][nwid]['dhclient.conf'],str):
            command.append('-c')
            command.append(conf['networks'][nwid]['dhclient.conf'])

    command.append(interface)
    if doas:
        command.insert(0,doas)
    if args.verbose:
        print(reduce( lambda a,b: a+' '+b, command))
    output = subprocess.check_output(args=command, universal_newlines=True,stderr=subprocess.STDOUT).rstrip()
    if args.verbose:
        print(output)
    if vpn:
        openvpn(connect=True)
    if status() is True and nwid not in conf['networks']:
        conf['networks'][nwid] = { 'nwid' : nwid, 'autoconnect' : True, 'vpn'   :  True }
        if wpakey:
            conf['networks'][nwid]['wpakey'] = wpakey
        with open(conf_file, 'w') as data_file:
            json.dump(conf,data_file,indent='\t',sort_keys=True)


parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', help='print messages (default)', action='store_true', default=True)
parser.add_argument('-s', '--silent', help='do not print any messages', action='store_true', default=False)
parser.add_argument('-a', '--auto', help='auto connect to saved available networks', action='store_true')
parser.add_argument('-c', '--connect', help='connect to specific saved network or specific nwid')
parser.add_argument('-d', '--disconnect', help='disconnect interface', action='store_true')
parser.add_argument('-l', '--list', help='scan and list available networks', action='store_true')
parser.add_argument('-nwid', help='nwid to connect to')
parser.add_argument('-wpakey', help='wpakey to use')
parser.add_argument('-bssid', help='bssid to use')
args = parser.parse_args()

if args.silent:
    args.verbose=False
if args.disconnect:
    if args.verbose:
        print('Disconnecting')
    disconnect()
    exit(0)
elif args.list:
    scan()
    ap_list = []
    for i in avail_ap:
        ap_list.append((print_nwid(i), avail_ap[i][0]['strength']))
    ap_list.sort(key=lambda t: t[1])
    if len(ap_list)>0:
        maxwidth = max(map(lambda x: len(x[0]), ap_list))
        print('nwid'.ljust(maxwidth) + 'strength')
        ap_list = map(lambda x: (x[0].ljust(maxwidth),x[1]), ap_list)
        for i in ap_list:
            print(i[0]+'\t'+i[1])
elif args.connect or args.auto:
    connect(network=args.connect,nwid=args.nwid,wpakey=args.wpakey,auto=args.auto,bssid=args.bssid)
else:
    status()
