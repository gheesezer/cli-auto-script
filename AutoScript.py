#
# Author: Guilherme César Da Silva <dasilvaguilhermecesar@gmail.com>
#
# AutoScript for Windows OS
#
#
import re
import os
import sys
import time
import serial  # LICENSE PYSERIAL

'''Copyright (c) 2001-2016 Chris Liechti <cliechti@gmx.net>
All Rights Reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials provided
    with the distribution.
  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------
Note:
Individual files contain the following tag instead of the full license text.
    SPDX-License-Identifier:    BSD-3-Clause
This enables machine processing of license information based on the SPDX
License Identifiers that are here available: http://spdx.org/licenses/'''


class Tools:

    """This class contains functions for checks and validations"""

    def __init__(self):

        self.cent_message = ''

        self.sear_tick_tag = ''
        self.sear_tick_data = ''
        self.sear_tick_pattern = ''
        self.sear_tick_string = ''
        self.sear_tick_found = ''

        self.valid_octe_ip = ''
        self.valid_octe_count = 0
        self.valid_octe_int = 0

        self.calc_netw_band = ''
        self.calc_netw_fOcteto = ''
        self.calc_netw_sOcteto = ''
        self.calc_netw_tOcteto = ''
        self.calc_netw_qOcteto_mask = ''
        self.calc_netw_qOcteto = ''
        self.calc_netw_cidr = ''
        self.calc_netw_check = ''
        self.calc_netw_first = ''
        self.calc_netw = 0
        self.calc_netw_last = ''
        self.calc_netw_qOctetoGateway = ''
        self.calc_netw_broadcast = ''
        self.calc_netw_mask = ''
        self.calc_netw_fband = ''
        self.calc_netw_lband = ''
        self.calc_netw_ipGateway = ''

        self.vali_rang_bits = 0
        self.vali_rang_qOcteto = ''
        self.vali_rang_step = 0
        self.vali_rang_int = 0
        self.vali_rang_bands = []

        self.sear_temp_tag = ''
        self.sear_temp_string = ''
        self.sear_temp_data = []
        self.sear_temp_linenumber = 0

        self.vali_rang_exten = ''
        self.vali_rang_gama = ''
        self.vali_rang_begin = ''
        self.vali_rang_end = ''
        self.vali_rang_size = 0
        self.vali_rang_qOcteto = ''

        self.run_ran_ext_tag = ''
        self.run_ran_ext_new_extension = 0
        self.run_ran_ext_extension = ''
        self.run_ran_ext_template = []
        self.run_ran_ext_prefix = ''
        self.run_ran_ext_suffix = ''
        self.run_ran_ext_line_number = 0

        self.run_key_ext_tag = ''
        self.run_key_ext_extension = ''
        self.run_key_ext_template = []
        self.run_key_ext_line_number = 0

        self.comp_rang_exten = ''
        self.comp_rang_gama = ''
        self.comp_rang_begin = ''
        self.comp_rang_end = ''
        self.comp_rang_check = ''
        self.comp_rang_prefix = ''
        self.comp_rang_suffix = ''

    def centralize_message(self, message):

        """Center with 80 pixels on each side of the character <\n>"""

        self.cent_message = message
        center = '\n'.join('{:^80}'.format(s) for s in message.split('\n'))
        return center

    def validate_octets(self, ip):

        """Receives an IPv4 IP and checks if it is valid"""

        self.valid_octe_ip = ip
        self.valid_octe_ip = self.valid_octe_ip.split('.')
        for self.valid_octe_int in self.valid_octe_ip:
            self.valid_octe_int = int(self.valid_octe_int)
            if 1 <= self.valid_octe_int <= 254:
                self.valid_octe_count += 1
            else:
                return None
            pass
        pass
        if self.valid_octe_count == 4:
            self.valid_octe_ip = '.'.join(self.valid_octe_ip)
            return self.valid_octe_ip
        else:
            return None
        pass

    def validate_range_ip(self, bit, qocteto):

        """Receives the fourth octet (Ex. 10.0.0.4/30 - fourth octet = 4) of the IPV4 range and the bit value (CIDR)
         of the netmask (Ex. 10.0.0.4/30 - CIDR = 30) and performs a comparison to identify whether the mask conforms
         to the reported IP range."""

        self.vali_rang_qOcteto = qocteto
        self.vali_rang_bits = int(bit)
        self.vali_rang_qOcteto = int(self.vali_rang_qOcteto)
        if self.vali_rang_bits == 30:
            self.vali_rang_step = 4
        elif self.vali_rang_bits == 29:
            self.vali_rang_step = 8
        elif self.vali_rang_bits == 28:
            self.vali_rang_step = 16
        elif self.vali_rang_bits == 27:
            self.vali_rang_step = 32
        elif self.vali_rang_bits == 26:
            self.vali_rang_step = 64
        elif self.vali_rang_bits == 25:
            self.vali_rang_step = 128
        elif self.vali_rang_bits == 24:
            self.vali_rang_step = 254
        else:
            return False
        for self.vali_rang_int in range(0, 255, self.vali_rang_step):
            self.vali_rang_bands.append(self.vali_rang_int)
        if self.vali_rang_qOcteto in self.vali_rang_bands:
            return True
        else:
            return False

    def calculate_network_mask(self, band):

        """Receives a range of IPv4 (Ex. 192.168.0.0/24) separates the IP by octets and bit of the mask and performs
        the calculations to identify which are the valid IPs and the Broadcast, returns the first available IP of the
        range, the last available IP of the range, the last valid IP assigned as Gateway, IP Broadcast, and the
        Calculated Network Mask."""

        self.calc_netw_band = band
        self.calc_netw_fOcteto, self.calc_netw_sOcteto, self.calc_netw_tOcteto, self.calc_netw_qOcteto_mask = \
            self.calc_netw_band.split('.')
        self.calc_netw_qOcteto, self.calc_netw_cidr = self.calc_netw_qOcteto_mask.split('/')
        self.calc_netw_check = tools.validate_range_ip(self.calc_netw_cidr, self.calc_netw_qOcteto)
        if self.calc_netw_check:
            self.calc_netw = int(self.calc_netw_qOcteto)
            if self.calc_netw_cidr == '30':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 2)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 2)
                self.calc_netw_broadcast = str(self.calc_netw + 3)
                self.calc_netw_mask = '255.255.255.252'
            elif self.calc_netw_cidr == '29':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 5)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 6)
                self.calc_netw_broadcast = str(self.calc_netw + 7)
                self.calc_netw_mask = '255.255.255.248'
            elif self.calc_netw_cidr == '28':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 13)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 14)
                self.calc_netw_broadcast = str(self.calc_netw + 15)
                self.calc_netw_mask = '255.255.255.240'
            elif self.calc_netw_cidr == '27':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 29)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 30)
                self.calc_netw_broadcast = str(self.calc_netw + 31)
                self.calc_netw_mask = '255.255.255.224'
            elif self.calc_netw_cidr == '26':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 61)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 62)
                self.calc_netw_broadcast = str(self.calc_netw + 63)
                self.calc_netw_mask = '255.255.255.192'
            elif self.calc_netw_cidr == '25':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 125)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 126)
                self.calc_netw_broadcast = str(self.calc_netw + 127)
                self.calc_netw_mask = '255.255.255.128'
            elif self.calc_netw_cidr == '24':
                self.calc_netw_first = str(self.calc_netw + 1)
                self.calc_netw_last = str(self.calc_netw + 253)
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 254)
                self.calc_netw_broadcast = str(self.calc_netw + 255)
                self.calc_netw_mask = '255.255.255.0'
            else:
                return None
        else:
            return None
        self.calc_netw_fband = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' +
            self.calc_netw_first)
        self.calc_netw_lband = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' +
            self.calc_netw_last)
        self.calc_netw_ipGateway = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' +
            self.calc_netw_qOctetoGateway)
        self.calc_netw_broadcast = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' +
            self.calc_netw_broadcast)
        return self.calc_netw_fband, self.calc_netw_lband, self.calc_netw_ipGateway, \
               self.calc_netw_broadcast, self.calc_netw_mask

    def search_in_ticket(self, tag, data, pattern):

        """Searches for a specified string within a list and returns only the required information."""

        self.sear_tick_tag = tag
        self.sear_tick_data = data
        self.sear_tick_pattern = pattern
        for self.sear_tick_string in self.sear_tick_data:
            re.search(self.sear_tick_tag, self.sear_tick_string)
            if re.search(self.sear_tick_tag, self.sear_tick_string):
                self.sear_tick_found = re.findall(self.sear_tick_pattern, self.sear_tick_string)
                self.sear_tick_found = ''.join(self.sear_tick_found)
                return self.sear_tick_found
            else:
                # print('\nNo match was found')
                continue
            pass
        pass
        return None

    def search_in_template(self, tag, data):

        """Searches for a specified string within a list and returns only the required information."""

        self.sear_temp_tag = tag
        self.sear_temp_data = data

        for self.sear_temp_string in self.sear_temp_data:
            re.search(self.sear_temp_tag, self.sear_temp_string)
            # print('Searching for "%s" in \n\n%s' % (self.sear_temp_tag, self.sear_temp_string ))
            if re.search(self.sear_temp_tag, self.sear_temp_string):
                # print('Match was foud.\n')
                self.sear_temp_linenumber = self.sear_temp_data.index(self.sear_temp_string)
                return self.sear_temp_linenumber
            else:
                # print('\nNo match was Foud\n')
                continue
            pass
        pass

    def validate_range_extension(self, extensions):

        """Receives an extension or a range of extensions to and performs a pattern check.
        Ex. 1932000000 or 1932000000 ~ 1932000099"""

        self.vali_rang_exten = extensions
        if '~' in self.vali_rang_exten:
            self.vali_rang_gama = self.vali_rang_exten.split('~')
            self.vali_rang_begin, self.vali_rang_end = self.vali_rang_gama
            if self.vali_rang_begin.isnumeric() and self.vali_rang_end.isnumeric:
                self.vali_rang_size = int(len(self.vali_rang_begin) + len(self.vali_rang_end))
                if self.vali_rang_size == 20:
                    return True
                else:
                    return False
            else:
                return False
        else:
            if self.vali_rang_exten.isnumeric():
                self.vali_rang_size = int(len(self.vali_rang_exten))
                if self.vali_rang_size == 10:
                    return True
                else:
                    return False
                pass
            else:
                return False

    def run_range_extension(self, tag, new_extension, extension, template):

        """Inserts numbers of extensions into the model according to the growing sequence received."""

        self.run_ran_ext_tag = tag
        self.run_ran_ext_new_extension = new_extension
        self.run_ran_ext_extension = extension
        self.run_ran_ext_template = template

        if '~' in self.run_ran_ext_extension:
            self.run_ran_ext_prefix, self.run_ran_ext_suffix = tools.compare_range(self.run_ran_ext_extension)

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'gw manipulations src-number-map-tel2ip ' + str(
                                                 self.run_ran_ext_new_extension) + '\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'src-prefix "' + self.run_ran_ext_suffix + '"\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'num-of-digits-to-leave 0\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'prefix-to-add "' + self.run_ran_ext_prefix + '"\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'activate\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'exit\n')

            self.run_ran_ext_new_extension += 1
        else:
            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'gw manipulations src-number-map-tel2ip ' + str(
                                                 self.run_ran_ext_new_extension) + '\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'num-of-digits-to-leave 0\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'prefix-to-add "' + self.run_ran_ext_extension + '"\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'activate\n')

            self.run_ran_ext_line_number = (tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'exit\n')

        self.run_ran_ext_new_extension += 1
        return self.run_ran_ext_template

    def run_key_extension(self, tag, extension, template):

        """Inserts a unique extension number.."""

        self.run_key_ext_tag = tag
        self.run_key_ext_extension = extension
        self.run_key_ext_template = template

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'gw manipulations src-number-map-tel2ip 0\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'num-of-digits-to-leave 0\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number,
                                         'prefix-to-add "' + self.run_key_ext_extension + '"\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'activate\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'exit\n')

        return self.run_key_ext_template

    def compare_range(self, extensions):

        """Compares two telephone numbers and identifies the variations, changes the variation by 'X' which equals
            0 ~ 9 on the router"""

        self.comp_rang_exten = extensions
        self.comp_rang_gama = self.comp_rang_exten.split('~')
        self.comp_rang_begin, self.comp_rang_end = self.comp_rang_gama
        if self.comp_rang_begin[-1] != self.comp_rang_end[-1]:
            self.comp_rang_check = [x for x in self.comp_rang_end]
            self.comp_rang_check[-1] = 'X'
            if self.comp_rang_begin[-2] != self.comp_rang_end[-2]:
                self.comp_rang_check[-2] = 'X'
        self.comp_rang_prefix = [x for x in self.comp_rang_check[:6]]
        self.comp_rang_suffix = [x for x in self.comp_rang_check[6:10]]
        self.comp_rang_prefix = ''.join(self.comp_rang_prefix)
        self.comp_rang_suffix = ''.join(self.comp_rang_suffix)
        return self.comp_rang_prefix, self.comp_rang_suffix


class OS:

    """This class is responsible for the attributes of the service order that is reported by the user."""

    def __init__(self):

        self.id_os = ''
        self.size_id = 0

        self.product = ''

        self.hostname = ''
        self.size_host = 0

        self.circuit = ''
        self.size_circ = 0

        self.vlan = ''

        self.wan = ''

        self.lan = ''

        self.speed = ''

        self.signaling = ''

        self.channel = 0

        self.os_host_tag = 'SW: '
        self.os_host_pattern = '[^SW: \n]'
        self.os_host_tag2 = '(HOSTNAME)'

        self.os_inter_circ_tag = 'ID DO SERVIÇO = '
        self.os_inter_circ_pattern = '[^A-Za-z:=çÇ \t\n]+'
        self.os_inter_circ_tag2 = '(CIRCUITO DADOS)'

        self.os_inter_vlan_tag = 'VLAN: '
        self.os_inter_vlan_pattern = '[^A-Za-z: \t\n]+'
        self.os_inter_vlan_tag2 = '(VLAN DADOS)'

        self.os_inter_wan_tag = 'Endereco IP WAN : '
        self.os_inter_wan_pattern = '[^A-Za-z: \t\n]+'
        self.os_inter_wan_tag2 = '(WAN DE DADOS MASCARA)'
        self.os_inter_wan_tag3 = '(WAN DADOS CALC)'
        self.os_inter_wan_tag4 = '(WAN DE DADOS PE)'

        self.os_inter_lan_tag = 'Endereco IP LAN : '
        self.os_inter_lan_pattern = '[^A-Za-z: \t\n]+'
        self.os_inter_lan_tag2 = '(LAN DE DADOS MASCARA)'
        self.os_inter_lan_tag3 = '(LAN DE DADOS BROAD)'
        self.os_inter_lan_tag4 = '(LAN DE DADOS CALC)'

        self.os_inter_speed_tag = 'Velocidade = '
        self.os_inter_speed_pattern = '[^A-Za-z:= \t\n]+'
        self.os_inter_speed_tag2 = '(VELOCIDADE)'

        self.os_voip_circ_tag = 'ID DO SERVIÇO = '
        self.os_voip_circ_pattern = '[^A-Za-z:=çÇ \t\n]+'
        self.os_voip_circ_tag2 = '(CIRCUITO VOIP)'

        self.os_voip_vlan_tag = 'VLAN: '
        self.os_voip_vlan_pattern = '[^A-Za-z: \t\n]+'
        self.os_voip_vlan_tag2 = '(VLAN VOIP)'

        self.os_voip_wan_tag = 'Endereco IP WAN : '
        self.os_voip_wan_pattern = '[^A-Za-z: \t\n]+'
        self.os_voip_wan_tag2 = '(WAN DE VOIP MASCARA)'

        self.os_voip_lan_tag = 'Endereco IP LAN : '
        self.os_voip_lan_pattern = '[^A-Za-z: \t\n]+'
        self.os_voip_lan_tag2 = '(LAN DE VOIP MASCARA)'

        self.os_voip_sbc_tag = 'IP SBC: '
        self.os_voip_sbc_pattern = '[^A-Za-z: \t\n]+'
        self.os_voip_sbc_tag2 = '(SBC)'

        self.os_voip_channel_tag = 'CANAIS: '
        self.os_voip_channel_pattern = '[^A-Za-z: \t\n]+'
        self.os_voip_channel_tag2 = 'last-b-channel '

        self.os_voip_man_add_ran_tag = '#FIM DOS RAMAIS'

        self.os_voip_auto_add_ran_tag = 'GAMA '
        self.os_voip_auto_add_ran_pattert = '[^A-Za-z: \t\n]+'
        self.os_voip_auto_add_ran_tag2 = '#FIM DOS RAMAIS'

        self.os_voip_man_add_key_tag = '#FIM DOS RAMAIS'

        self.os_voip_auto_add_key_tag = 'NUMERO CHAVE ='
        self.os_voip_auto_add_key_pattert = '[^A-Za-z: =\t\n]+'
        self.os_voip_auto_add_key_tag2 = '#FIM DOS RAMAIS'

        self.os_voip_billing_tag = 'Tarifação: '
        self.os_voip_billing_pattern = '[^Tarifação: \t\n]'
        self.os_voip_billing_tag2 = 'GAMA '

        self.os_voip_extension_tag = 'GAMA: '
        self.os_voip_extension_pattern = '[^A-Za-z: \t\n]+'

    def validate_id(self, id_os):

        """Validates the size of the Service Order number entered by the user."""

        self.id_os = id_os
        if self.id_os.isnumeric():
            self.size_id = len(self.id_os)
            if self.size_id <= 6:
                return self.id_os
            else:
                print(tools.centralize_message('\n\nOrdem de Serviço tem Apenas 6 Números!'))
                time.sleep(2)
        else:
            print(tools.centralize_message('\n\nDigite Apenas Números!'))
            time.sleep(2)
            return False  #

    def validate_product(self, product):

        """Validates whether it is a valid product to be configured."""

        self.product = product
        if self.product == 'Internet Link':
            return 'Internet Link'
        elif self.product == 'Voz Total':
            return 'Voz Total'
        elif self.product == 'Ponto de Acesso':
            return 'Ponto de Acesso'
        else:
            return None

    def validate_hostname(self, hostname):

        """Validate the hostname accepted by the router."""

        self.hostname = hostname
        self.size_host = len(self.hostname)
        if 15 <= self.size_host <= 30:
            self.hostname = self.hostname.replace('clm-sw-', 'cl-rt-')
            return self.hostname
        else:
            return None

    def validate_circuit(self, circuit):

        """Validate the circuit pattern to be configured."""

        self.circuit = circuit
        if self.circuit.isnumeric():
            self.size_circ = len(self.circuit)
            if self.size_circ <= 10:
                return self.circuit
            else:
                print(tools.centralize_message('\n\nDigite no máximo até 10 números!'))
                time.sleep(2)
        else:
            print(tools.centralize_message('\n\nDigite Apenas Números!'))
            time.sleep(2)
            return None

    def validate_vlan(self, vlan):

        """Validate the range of valid vlans."""

        self.vlan = vlan
        if self.vlan.isnumeric():
            self.vlan = int(self.vlan)
            if 0 < self.vlan <= 4000:
                return str(self.vlan)
            else:
                print(tools.centralize_message('\n\nDigite Vlan entre 1 e 4000!'))
                time.sleep(2)
                return None
        else:
            print(tools.centralize_message('\n\nDigite Apenas Números!'))
            time.sleep(2)
            return None

    def validate_wan(self, wan):

        """Validates the range and calculates valid WAN IPs."""

        self.wan = wan
        return tools.calculate_network_mask(self.wan)

    def validate_lan(self, lan):

        """Validates the range and calculates valid LAN IPs."""

        self.lan = lan
        return tools.calculate_network_mask(self.lan)

    def validate_speed(self, speed):

        """Calculates and converts the reported speed in Mbps to bps."""

        self.speed = speed
        if self.speed.isnumeric():
            self.speed = int(self.speed)
            if self.speed > 0:
                self.speed *= 1024
                return str(self.speed)
            else:
                return None
        else:
            print(tools.centralize_message('\n\nDigite Apenas Números!'))
            time.sleep(2)
            return None

    def validate_signaling(self, signaling):

        """Validates the voice signal to be configured."""

        self.signaling = signaling
        if self.signaling == 'R2':
            return 'R2'
        elif self.signaling == 'ISDN':
            return 'ISDN'

    def validate_sbc(self, sbc):

        """Validates the SBC IP octets."""

        self.sbc = sbc
        return tools.validate_octets(self.sbc)

    def validate_channel(self, channel):

        """Validates the valid channel interval for configuration."""

        self.channel = channel
        if self.channel.isnumeric():
            self.channel = int(self.channel)
            if 0 < self.channel <= 30:
                return str(self.channel)
            else:
                print(tools.centralize_message('\n\nDigite Canais entre 1 e 30!'))
                time.sleep(2)
                return None
        else:
            print(tools.centralize_message('\n\nDigite Apenas Números'))
            time.sleep(2)
            return None


class Product:

    """This class is responsible for identifying the type of product that will be configured in the equipment"""

    def __init__(self, equipment, product, tickets):

        self.prod_equipment = equipment
        self.prod_product = product
        self.prod_tickets = tickets

        self.audio_ivr2_hostname = None
        self.audio_ivr2_inter_circuit = None
        self.audio_ivr2_inter_vlan = None
        self.audio_ivr2_inter_wan = None
        self.audio_ivr2_inter_lan = None
        self.audio_ivr2_inter_speed = None
        self.audio_ivr2_voip_circuit = None
        self.audio_ivr2_voip_vlan = None
        self.audio_ivr2_voip_wan = None
        self.audio_ivr2_voip_lan = None
        self.audio_ivr2_voip_sbc = None
        self.audio_ivr2_voip_channel = None
        self.audio_ivr2_voip_billing = None

        self.audio_ivr2_archive = ''
        self.audio_ivr2_template = []

        self.facilities = OS()
        self.audio_ivr2_internet_link = []
        self.audio_ivr2_voz_total = []
        self.audio_ivr2_ponto_de_acesso = []

        self.host_hostname = ''
        self.host_template = []
        self.host_linenumber = 0

        self.circ_circuit_inter = ''
        self.circ_template_inter = []
        self.circ_linenumber_inter = 0

        self.vl_vlan_inter = ''
        self.vl_template_inter = []
        self.vl_linenumber_inter = 0
        self.vl_occurrence_inter = 0
        self.vl_string_inter = ''
        self.vl_int_inter = 0

        self.wan_inter_wan = ''
        self.wan_inter_template = []
        self.wan_inter_string = ''
        self.wan_inter_occurrences = 0
        self.wan_inter_occurrences1 = 0
        self.wan_inter_occurrences2 = 0
        self.wan_inter_fband = ''
        self.wan_inter_lband = ''
        self.wan_inter_ipGateway = ''
        self.wan_inter_broadcast = ''
        self.wan_inter_mask = ''
        self.wan_inter_search = ''
        self.wan_inter_line_number = 0

        self.lan_inter_wan = ''
        self.lan_inter_template = []
        self.lan_inter_string = ''
        self.lan_inter_occurrences = 0
        self.lan_inter_occurrences1 = 0
        self.lan_inter_occurrences2 = 0
        self.lan_inter_fband = ''
        self.lan_inter_lband = ''
        self.lan_inter_ipGateway = ''
        self.lan_inter_broadcast = ''
        self.lan_inter_mask = ''
        self.lan_inter_search = ''
        self.lan_inter_line_number = 0

        self.speed_speed_inter = ''
        self.speed_template_inter = []
        self.speed_linenumber_inter = 0
        self.speed_occurrence_inter = 0
        self.speed_string_inter = ''

        self.circ_circuit_voip = ''
        self.circ_template_voip = []
        self.circ_linenumber_voip = 0

        self.vl_vlan_voip = ''
        self.vl_template_voip = []
        self.vl_linenumber_voip = 0
        self.vl_occurrence_voip = 0
        self.vl_string_voip = ''

        self.wan_voip_wan = ''
        self.wan_voip_template = []
        self.wan_voip_string = ''
        self.wan_voip_occurrences = 0
        self.wan_voip_occurrences1 = 0
        self.wan_voip_occurrences2 = 0
        self.wan_voip_fband = ''
        self.wan_voip_lband = ''
        self.wan_voip_ipGateway = ''
        self.wan_voip_broadcast = ''
        self.wan_voip_mask = ''
        self.wan_voip_search = ''
        self.wan_voip_line_number = 0

        self.lan_voip_wan = ''
        self.lan_voip_template = []
        self.lan_voip_string = ''
        self.lan_voip_occurrences = 0
        self.lan_voip_occurrences1 = 0
        self.lan_voip_occurrences2 = 0
        self.lan_voip_fband = ''
        self.lan_voip_lband = ''
        self.lan_voip_ipGateway = ''
        self.lan_voip_broadcast = ''
        self.lan_voip_mask = ''
        self.lan_voip_search = ''
        self.lan_voip_line_number = 0

        self.sbc_voip_sbc = ''
        self.sbc_voip_template = []
        self.sbc_linenumber_voip = 0
        self.sbc_occurrence_voip = 0
        self.sbc_string_voip = ''

        self.ch_channel_voip = ''
        self.ch_template_voip = []
        self.ch_linenumber_voip = 0
        self.ch_occurrence_voip = 0
        self.ch_string_voip = ''

        self.man_add_ran_exten = ''
        self.man_add_ran_template = []
        self.man_add_ran_new_exten = 0
        self.man_add_ran_check = False
        self.man_add_ran_line_number = 0
        self.man_add_ran_add = ''

        self.auto_add_ran_exten = ''
        self.auto_add_ran_template = []
        self.auto_add_ran_ticket_voztotal = []
        self.auto_add_ran_new_exten = 0
        self.auto_add_ran_check = False

        self.man_add_key_exten = ''
        self.man_add_key_template = ''
        self.man_add_key_check = False

        self.auto_add_key_exten = ''
        self.auto_add_key_template = []
        self.auto_add_key_ticket_voztotal = []
        self.auto_add_key_new_exten = 0
        self.auto_add_key_check = False

        self.bi_billing_voip = ''
        self.bi_template_voip = []
        self.bi_ticket_voztotal = []
        self.bi_occurrence_voip = 0
        self.bi_new_extension = 0
        self.bi_billing_extension = ''

        self.gener_template = []

    def hostname(self, hostname, template):

        """Enter the "hostname" of the router in the default configuration template."""

        self.host_hostname = hostname
        self.host_template = template
        self.host_linenumber = tools.search_in_template(self.facilities.os_host_tag2, self.host_template)
        while True:
            if self.host_hostname is None:
                os.system('cls')
                self.host_hostname = input(tools.centralize_message(
                    main.banner + '\n\n\nDIGITE HOSTNAME:\tEx. cl-sw-cas-00001-empresa-01') + '\n\n\n Hostname > ')
                self.host_hostname = OS.validate_hostname(self, self.host_hostname)
                if self.host_hostname is None:
                    print(tools.centralize_message('\nHostname deve ter entre 15 e 30 caracteres!'))
                    time.sleep(2)
                    continue
                else:
                    self.host_template[self.host_linenumber] = self.host_template[self.host_linenumber].replace \
                        (self.facilities.os_host_tag2, self.host_hostname)
                    return self.host_template
            else:
                self.host_hostname = OS.validate_hostname(self, self.host_hostname)
                self.host_template[self.host_linenumber] = self.host_template[self.host_linenumber].replace \
                    (self.facilities.os_host_tag2, self.host_hostname)
                return self.host_template

    def circuit_inter(self, circuit, template):

        """Enter the circuit number in the default configuration template."""

        self.circ_circuit_inter = circuit
        self.circ_template_inter = template
        self.circ_linenumber_inter = tools.search_in_template(self.facilities.os_inter_circ_tag2,
                                                              self.circ_template_inter)
        while True:
            if self.circ_circuit_inter is None:
                os.system('cls')
                self.circ_circuit_inter = input(
                    tools.centralize_message(main.banner + '\n\n\nDigite ID do Circuito Internet Link:'
                                                           '\tEx. 0000000001') +
                    '\n\n\n Circuito de Internet Link > ')
                self.circ_circuit_inter = self.facilities.validate_circuit(self.circ_circuit_inter)
                if self.circ_circuit_inter is None:
                    continue
                else:
                    self.circ_template_inter[self.circ_linenumber_inter] = self.circ_template_inter[
                        self.circ_linenumber_inter].replace(self.facilities.os_inter_circ_tag2, self.circ_circuit_inter)
                    return self.circ_template_inter
            else:
                self.circ_circuit_inter = self.facilities.validate_circuit(self.circ_circuit_inter)
                self.circ_template_inter[self.circ_linenumber_inter] = self.circ_template_inter[
                    self.circ_linenumber_inter].replace(self.facilities.os_inter_circ_tag2, self.circ_circuit_inter)
                return self.circ_template_inter

    def vlan_inter(self, vlan, template):

        """Inserts the Internet VLAN into the default configuration template.."""

        self.vl_vlan_inter = vlan
        self.vl_template_inter = template
        for self.vl_string_inter in self.vl_template_inter:
            if self.facilities.os_inter_vlan_tag2 in self.vl_string_inter:
                self.vl_occurrence_inter += 1
        while True:
            if self.vl_vlan_inter is None:
                os.system('cls')
                self.vl_vlan_inter = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite Vlan de Internet Link:\tEx. 10') + '\n\n\n Vlan de Internet Link > ')
                self.vl_vlan_inter = self.facilities.validate_vlan(self.vl_vlan_inter)
                if self.vl_vlan_inter is None:
                    continue
                else:
                    for self.vl_string_inter in range(self.vl_occurrence_inter):
                        self.vl_linenumber_inter = tools.search_in_template(self.facilities.os_inter_vlan_tag2,
                                                                            self.vl_template_inter)
                        self.vl_template_inter[self.vl_linenumber_inter] = self.vl_template_inter[
                            self.vl_linenumber_inter].replace(self.facilities.os_inter_vlan_tag2, self.vl_vlan_inter)
                    return self.vl_template_inter
            else:
                self.vl_vlan_inter = self.facilities.validate_vlan(self.vl_vlan_inter)
                for self.vl_int_inter in range(self.vl_occurrence_inter):
                    self.vl_linenumber_inter = tools.search_in_template(self.facilities.os_inter_vlan_tag2,
                                                                        self.vl_template_inter)
                    self.vl_template_inter[self.vl_linenumber_inter] = self.vl_template_inter[
                        self.vl_linenumber_inter].replace(self.facilities.os_inter_vlan_tag2, self.vl_vlan_inter)
                return self.vl_template_inter

    def wan_inter(self, wan, template):

        """Inserts the WAN IPs calculated in the default configuration template according to each field."""

        self.wan_inter_wan = wan
        self.wan_inter_template = template

        for self.wan_inter_string in self.wan_inter_template:
            if self.facilities.os_inter_wan_tag2 in self.wan_inter_string:
                self.wan_inter_occurrences += 1

        for self.wan_inter_string in self.wan_inter_template:
            if self.facilities.os_inter_wan_tag3 in self.wan_inter_string:
                self.wan_inter_occurrences1 += 1

        for self.wan_inter_string in self.wan_inter_template:
            if self.facilities.os_inter_wan_tag4 in self.wan_inter_string:
                self.wan_inter_occurrences2 += 1

        while True:
            if self.wan_inter_wan is None:
                os.system('cls')
                self.wan_inter_wan = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite a faixa Wan de Internet Link:\tEx. 200.125.78.28/30') +
                                           '\n\n\n Wan de Internet Link > ')
                try:
                    self.wan_inter_fband, self.wan_inter_lband, self.wan_inter_ipGateway, self.wan_inter_broadcast, \
                    self.wan_inter_mask = (self.facilities.validate_wan(self.wan_inter_wan))
                except ValueError:
                    print(tools.centralize_message('\n Entrada Invalida!'))
                    time.sleep(2)
                    self.wan_inter_wan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n Faixa de Wan Invalida!'))
                    time.sleep(2)
                    self.wan_inter_wan = None
                    continue
                for self.wan_inter_search in range(self.wan_inter_occurrences):
                    self.wan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_wan_tag2, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[
                        self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag2,
                                                            self.wan_inter_fband + ' ' + self.wan_inter_mask)

                for self.wan_inter_search in range(self.wan_inter_occurrences1):
                    self.wan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_wan_tag3, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[
                        self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag3, self.wan_inter_fband)

                for self.wan_inter_search in range(self.wan_inter_occurrences2):
                    self.wan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_wan_tag4, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[
                        self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag4, self.wan_inter_lband)
                return self.wan_inter_template
            else:
                try:
                    self.wan_inter_fband, self.wan_inter_lband, self.wan_inter_ipGateway, self.wan_inter_broadcast, \
                    self.wan_inter_mask = (self.facilities.validate_wan(self.wan_inter_wan))
                except ValueError:
                    self.wan_inter_wan = None
                    continue
                except TypeError:
                    self.wan_inter_wan = None
                    continue
                for self.wan_inter_search in range(self.wan_inter_occurrences):
                    self.wan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_wan_tag2, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[
                        self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag2,
                                                            self.wan_inter_fband + ' ' + self.wan_inter_mask)

                for self.wan_inter_search in range(self.wan_inter_occurrences1):
                    self.wan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_wan_tag3, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[
                        self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag3, self.wan_inter_fband)

                for self.wan_inter_search in range(self.wan_inter_occurrences2):
                    self.wan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_wan_tag4, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[
                        self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag4, self.wan_inter_lband)
                return self.wan_inter_template

    def lan_inter(self, lan, template):

        """Inserts the LAN IPs calculated in the default configuration template according to each field."""

        self.lan_inter_lan = lan
        self.lan_inter_template = template

        for self.lan_inter_string in self.lan_inter_template:
            if self.facilities.os_inter_lan_tag2 in self.lan_inter_string:
                self.lan_inter_occurrences += 1

        for self.lan_inter_string in self.lan_inter_template:
            if self.facilities.os_inter_lan_tag3 in self.lan_inter_string:
                self.lan_inter_occurrences1 += 1

        for self.lan_inter_string in self.lan_inter_template:
            if self.facilities.os_inter_lan_tag4 in self.lan_inter_string:
                self.lan_inter_occurrences2 += 1

        while True:
            if self.lan_inter_lan is None:
                os.system('cls')
                self.lan_inter_lan = input(
                    tools.centralize_message(
                        main.banner + '\n\n\nDigite a faixa Lan de Internet Link:\tEx. 200.125.78.24/29') +
                    '\n\n\n Lan de Internet Link > ')
                try:
                    self.lan_inter_fband, self.lan_inter_lband, self.lan_inter_ipGateway, self.lan_inter_broadcast, \
                    self.lan_inter_mask = (self.facilities.validate_lan(self.lan_inter_lan))
                except ValueError:
                    print(tools.centralize_message('\n Entrada Invalida!'))
                    time.sleep(2)
                    self.lan_inter_lan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n Faixa de Lan Invalida!'))
                    time.sleep(2)
                    self.lan_inter_lan = None
                    continue
                for self.lan_inter_search in range(self.lan_inter_occurrences):
                    self.lan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_lan_tag2, self.lan_inter_template))
                    self.lan_inter_template[self.lan_inter_line_number] = self.lan_inter_template[
                        self.lan_inter_line_number].replace(self.facilities.os_inter_lan_tag2,
                                                            self.lan_inter_fband + ' ' + self.lan_inter_mask)
                for self.lan_inter_search in range(self.lan_inter_occurrences1):
                    self.lan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_lan_tag3, self.lan_inter_template))
                    self.lan_inter_template[self.lan_inter_line_number] = self.lan_inter_template[
                        self.lan_inter_line_number].replace(self.facilities.os_inter_lan_tag3, self.lan_inter_fband)
                for self.lan_inter_search in range(self.lan_inter_occurrences2):
                    self.lan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_lan_tag4, self.lan_inter_template))
                    self.lan_inter_template[self.lan_inter_line_number] = self.lan_inter_template[
                        self.lan_inter_line_number].replace(self.facilities.os_inter_lan_tag4, self.lan_inter_lband)
                return self.lan_inter_template
            else:
                try:
                    self.lan_inter_fband, self.lan_inter_lband, self.lan_inter_ipGateway, self.lan_inter_broadcast, \
                    self.lan_inter_mask = (self.facilities.validate_lan(self.lan_inter_lan))
                except ValueError:
                    self.lan_inter_lan = None
                    continue
                except TypeError:
                    self.lan_inter_lan = None
                    continue
                for self.lan_inter_search in range(self.lan_inter_occurrences):
                    self.lan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_lan_tag2, self.lan_inter_template))
                    self.lan_inter_template[self.lan_inter_line_number] = self.lan_inter_template[
                        self.lan_inter_line_number].replace(self.facilities.os_inter_lan_tag2,
                                                            self.lan_inter_ipGateway + ' ' + self.lan_inter_mask)
                for self.lan_inter_search in range(self.lan_inter_occurrences1):
                    self.lan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_lan_tag3, self.lan_inter_template))
                    self.lan_inter_template[self.lan_inter_line_number] = self.lan_inter_template[
                        self.lan_inter_line_number].replace(self.facilities.os_inter_lan_tag3, self.lan_inter_broadcast)
                for self.lan_inter_search in range(self.lan_inter_occurrences2):
                    self.lan_inter_line_number = (
                        tools.search_in_template(self.facilities.os_inter_lan_tag4, self.lan_inter_template))
                    self.lan_inter_template[self.lan_inter_line_number] = self.lan_inter_template[
                        self.lan_inter_line_number].replace(self.facilities.os_inter_lan_tag4, self.lan_inter_ipGateway)
            return self.lan_inter_template

    def speed_inter(self, speed, template):

        """Inserts the internert speed into 'bps' in the default configuration template."""

        self.speed_speed_inter = speed
        self.speed_template_inter = template

        while True:
            if self.speed_speed_inter is None:
                os.system('cls')
                self.speed_speed_inter = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite Velocidade de Internet Link:\tEx. 100') +
                                               '\n\n\n Velocidade de Internet Link > ')
                self.speed_speed_inter = self.facilities.validate_speed(self.speed_speed_inter)
                if self.speed_speed_inter is None:
                    continue
                else:
                    self.speed_linenumber_inter = tools.search_in_template(self.facilities.os_inter_speed_tag2,
                                                                           self.speed_template_inter)
                    self.speed_template_inter[self.speed_linenumber_inter] = self.speed_template_inter[
                        self.speed_linenumber_inter].replace(self.facilities.os_inter_speed_tag2,
                                                             self.speed_speed_inter)
                    return self.speed_template_inter
            else:
                self.speed_speed_inter = self.facilities.validate_speed(self.speed_speed_inter)
                self.speed_linenumber_inter = tools.search_in_template(self.facilities.os_inter_speed_tag2,
                                                                       self.speed_template_inter)
                self.speed_template_inter[self.speed_linenumber_inter] = self.speed_template_inter[
                    self.speed_linenumber_inter].replace(self.facilities.os_inter_speed_tag2, self.speed_speed_inter)
                return self.speed_template_inter

    def circuit_voip(self, circuit, template):

        """Enter the circuit number in the default configuration template."""

        self.circ_circuit_voip = circuit
        self.circ_template_voip = template
        self.circ_linenumber_voip = tools.search_in_template(self.facilities.os_voip_circ_tag2, self.circ_template_voip)
        while True:
            if self.circ_circuit_voip is None:
                os.system('cls')
                self.circ_circuit_voip = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite ID do Circuito Voz Total:\tEx. 0000000002')
                                               + '\n\n\n Circuito de Voz Total > ')
                self.circ_circuit_voip = self.facilities.validate_circuit(self.circ_circuit_voip)
                if self.circ_circuit_voip is None:
                    continue
                else:
                    self.circ_template_voip[self.circ_linenumber_voip] = self.circ_template_voip[
                        self.circ_linenumber_voip].replace(self.facilities.os_voip_circ_tag2, self.circ_circuit_voip)
                    return self.circ_template_voip
            else:
                self.circ_circuit_voip = self.facilities.validate_circuit(self.circ_circuit_voip)
                self.circ_template_voip[self.circ_linenumber_voip] = self.circ_template_voip[
                    self.circ_linenumber_voip].replace(self.facilities.os_voip_circ_tag2, self.circ_circuit_voip)
                return self.circ_template_voip

    def vlan_voip(self, vlan, template):

        """Inserts the Voip VLAN into the default configuration template.."""

        self.vl_vlan_voip = vlan
        self.vl_template_voip = template
        for self.vl_string_voip in self.vl_template_voip:
            if self.facilities.os_voip_vlan_tag2 in self.vl_string_voip:
                self.vl_occurrence_voip += 1
        while True:
            if self.vl_vlan_voip is None:
                os.system('cls')
                self.vl_vlan_voip = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite Vlan Voz Total:\tEx. 11') + '\n\n\n Vlan de Voz Total > ')
                self.vl_vlan_voip = self.facilities.validate_vlan(self.vl_vlan_voip)
                if self.vl_vlan_voip is None:
                    continue
                else:
                    for self.vl_string_voip in range(self.vl_occurrence_voip):
                        self.vl_linenumber_voip = tools.search_in_template(self.facilities.os_voip_vlan_tag2,
                                                                           self.vl_template_voip)
                        self.vl_template_voip[self.vl_linenumber_voip] = self.vl_template_voip[
                            self.vl_linenumber_voip].replace(self.facilities.os_voip_vlan_tag2, self.vl_vlan_voip)
                    return self.vl_template_voip
            else:
                self.vl_vlan_voip = self.facilities.validate_vlan(self.vl_vlan_voip)
                for self.vl_string_voip in range(self.vl_occurrence_voip):
                    self.vl_linenumber_voip = tools.search_in_template(self.facilities.os_voip_vlan_tag2,
                                                                       self.vl_template_voip)
                    self.vl_template_voip[self.vl_linenumber_voip] = self.vl_template_voip[
                        self.vl_linenumber_voip].replace(self.facilities.os_voip_vlan_tag2, self.vl_vlan_voip)
                return self.vl_template_voip

    def wan_voip(self, wan, template):

        """Inserts the WAN IPs calculated in the default configuration template according to each field."""

        self.wan_voip_wan = wan
        self.wan_voip_template = template

        for self.wan_voip_string in self.wan_voip_template:
            if self.facilities.os_voip_wan_tag2 in self.wan_voip_string:
                self.wan_voip_occurrences += 1

        while True:
            if self.wan_voip_wan is None:
                os.system('cls')
                self.wan_voip_wan = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite a faixa Wan de Voz Total:\tEx. 10.55.235.180/30')
                                          + '\n\n\n Wan de Voz Total > ')
                try:
                    self.wan_voip_fband, self.wan_voip_lband, self.wan_voip_ipGateway, self.wan_voip_broadcast, \
                    self.wan_voip_mask = (self.facilities.validate_wan(self.wan_voip_wan))
                except ValueError:
                    print(tools.centralize_message('\n\nEntrada Invalida!'))
                    time.sleep(2)
                    self.wan_voip_wan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n\nFaixa de Wan Invalida!'))
                    time.sleep(2)
                    self.wan_voip_wan = None
                    continue
                for self.wan_voip_search in range(self.wan_voip_occurrences):
                    self.wan_voip_line_number = (
                        tools.search_in_template(self.facilities.os_voip_wan_tag2, self.wan_voip_template))
                    self.wan_voip_template[self.wan_voip_line_number] = self.wan_voip_template[
                        self.wan_voip_line_number].replace(self.facilities.os_voip_wan_tag2,
                                                           self.wan_voip_fband + ' ' + self.wan_voip_mask)
                return self.wan_voip_template
            else:
                try:
                    self.wan_voip_fband, self.wan_voip_lband, self.wan_voip_ipGateway, self.wan_voip_broadcast, \
                    self.wan_voip_mask = (self.facilities.validate_wan(self.wan_voip_wan))
                except ValueError:
                    self.wan_voip_wan = None
                    continue
                except TypeError:
                    self.wan_voip_wan = None
                    continue
                for self.wan_voip_search in range(self.wan_voip_occurrences):
                    self.wan_voip_line_number = (
                        tools.search_in_template(self.facilities.os_voip_wan_tag2, self.wan_voip_template))
                    self.wan_voip_template[self.wan_voip_line_number] = self.wan_voip_template[
                        self.wan_voip_line_number].replace(self.facilities.os_voip_wan_tag2,
                                                           self.wan_voip_fband + ' ' + self.wan_voip_mask)
                return self.wan_voip_template

    def lan_voip(self, lan, template):

        """Inserts the LAN IPs calculated in the default configuration template according to each field."""

        self.lan_voip_lan = lan
        self.lan_voip_template = template

        for self.lan_voip_string in self.lan_voip_template:
            if self.facilities.os_voip_lan_tag2 in self.lan_voip_string:
                self.lan_voip_occurrences += 1

        while True:
            if self.lan_voip_lan is None:
                os.system('cls')
                self.lan_voip_lan = input(
                    tools.centralize_message(
                        main.banner + '\n\n\nDigite a faixa Lan de Voz Total:\tEx. 187.22.252.232/29')
                    + '\n\n\n Lan de Voz Total > ')
                try:
                    self.lan_voip_fband, self.lan_voip_lband, self.lan_voip_ipGateway, self.lan_voip_broadcast, \
                    self.lan_voip_mask = (self.facilities.validate_lan(self.lan_voip_lan))
                except ValueError:
                    print(tools.centralize_message('\n\nEntrada Invalida!'))
                    time.sleep(2)
                    self.lan_voip_lan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n\nFaixa de Lan Invalida!'))
                    time.sleep(2)
                    self.lan_voip_lan = None
                    continue
                for self.lan_voip_search in range(self.lan_voip_occurrences):
                    self.lan_voip_line_number = (
                        tools.search_in_template(self.facilities.os_voip_lan_tag2, self.lan_voip_template))
                    self.lan_voip_template[self.lan_voip_line_number] = self.lan_voip_template[
                        self.lan_voip_line_number].replace(self.facilities.os_voip_lan_tag2,
                                                           self.lan_voip_fband + ' ' + self.lan_voip_mask)
                return self.lan_voip_template
            else:
                try:
                    self.lan_voip_fband, self.lan_voip_lband, self.lan_voip_ipGateway, self.lan_voip_broadcast, \
                    self.lan_voip_mask = (self.facilities.validate_lan(self.lan_voip_lan))
                except ValueError:
                    self.lan_voip_lan = None
                    continue
                except TypeError:
                    self.lan_voip_lan = None
                    continue
                for self.lan_voip_search in range(self.lan_voip_occurrences):
                    self.lan_voip_line_number = (
                        tools.search_in_template(self.facilities.os_voip_lan_tag2, self.lan_voip_template))
                    self.lan_voip_template[self.lan_voip_line_number] = self.lan_voip_template[
                        self.lan_voip_line_number].replace(self.facilities.os_voip_lan_tag2,
                                                           self.lan_voip_fband + ' ' + self.lan_voip_mask)
            return self.lan_voip_template

    def sbc_voip(self, sbc, template):

        """Inserts the validated SBC IPs into the default configuration template according to each field."""

        self.sbc_voip_sbc = sbc
        self.sbc_voip_template = template

        for self.sbc_voip_string in self.sbc_voip_template:
            if self.facilities.os_voip_sbc_tag2 in self.sbc_voip_string:
                self.sbc_occurrence_voip += 1

        while True:
            if self.sbc_voip_sbc is None:
                os.system('cls')
                self.sbc_voip_sbc = input(
                    tools.centralize_message(
                        main.banner + '\n\n\nDigite o IP SBC de Voz Total:\tEx. 172.26.154.70')
                    + '\n\n\n SBC de Voz Total > ')
                self.sbc_voip_sbc = (self.facilities.validate_sbc(self.sbc_voip_sbc))
                for self.sbc_voip_search in range(self.sbc_occurrence_voip):
                    self.sbc_linenumber_voip = (
                        tools.search_in_template(self.facilities.os_voip_sbc_tag2, self.sbc_voip_template))
                    self.sbc_voip_template[self.sbc_linenumber_voip] = self.sbc_voip_template[
                        self.sbc_linenumber_voip].replace(self.facilities.os_voip_sbc_tag2, self.sbc_voip_sbc)
                return self.sbc_voip_template
            else:
                self.sbc_voip_sbc = (self.facilities.validate_sbc(self.sbc_voip_sbc))
                for self.sbc_voip_search in range(self.sbc_occurrence_voip):
                    self.sbc_linenumber_voip = (
                        tools.search_in_template(self.facilities.os_voip_sbc_tag2, self.sbc_voip_template))
                    self.sbc_voip_template[self.sbc_linenumber_voip] = self.sbc_voip_template[
                        self.sbc_linenumber_voip].replace(self.facilities.os_voip_sbc_tag2, self.sbc_voip_sbc)
            return self.sbc_voip_template

    def channel_voip(self, channel, template):

        """Inserts the number of channels in the default template."""

        self.ch_channel_voip = channel
        self.ch_template_voip = template
        for self.ch_string_voip in self.ch_template_voip:
            if self.facilities.os_voip_channel_tag2 in self.ch_string_voip:
                self.ch_occurrence_voip += 1
        while True:
            if self.ch_channel_voip is None:
                os.system('cls')
                self.ch_channel_voip = input(tools.centralize_message(
                    main.banner + '\n\n\nDigite Canais de Voz Total:\tEx. 30') + '\n\n\n Canais de Voz Total > ')
                self.ch_channel_voip = self.facilities.validate_channel(self.ch_channel_voip)
                if self.ch_channel_voip is None:
                    continue
                else:
                    for self.ch_string_voip in range(self.ch_occurrence_voip):
                        self.ch_linenumber_voip = tools.search_in_template(self.facilities.os_voip_channel_tag2,
                                                                           self.ch_template_voip)
                        self.ch_template_voip[self.ch_linenumber_voip] = self.ch_template_voip[
                            self.ch_linenumber_voip].replace('31', self.ch_channel_voip)
                    return self.ch_template_voip
            else:
                self.ch_channel_voip = self.facilities.validate_channel(self.ch_channel_voip)
                for self.ch_string_voip in range(self.ch_occurrence_voip):
                    self.ch_linenumber_voip = tools.search_in_template(self.facilities.os_voip_channel_tag2,
                                                                       self.ch_template_voip)

                    self.ch_template_voip[self.ch_linenumber_voip] = self.ch_template_voip[
                        self.ch_linenumber_voip].replace('31', self.ch_channel_voip)
                return self.ch_template_voip

    def man_add_range(self, template):

        """Inserts the manually entered extensions into the default template as many times as necessary."""

        self.man_add_ran_template = template
        while self.man_add_ran_new_exten != -1:
            os.system('cls')
            self.man_add_ran_exten = input(tools.centralize_message(
                main.banner + '\nDigite os Ramais:\tEx. 1935544900~1935544999 ou 1935544900') + '\n\n Ramal > ')
            self.man_add_ran_check = tools.validate_range_extension(self.man_add_ran_exten)
            if self.man_add_ran_check:
                self.man_add_ran_template = tools.run_range_extension(self.facilities.os_voip_man_add_ran_tag,
                                                                      self.man_add_ran_new_exten,
                                                                      self.man_add_ran_exten, self.man_add_ran_template)
                while True:
                    os.system('cls')
                    print(tools.centralize_message(main.banner))
                    self.man_add_ran_add = input(
                        tools.centralize_message('\nAdicionar uma outra gama de ramais?') + "\n\n'S' ou 'N' > ")
                    if self.man_add_ran_add == 's' or self.man_add_ran_add == 'S':
                        break
                    elif self.man_add_ran_add == 'n' or self.man_add_ran_add == 'N':
                        self.man_add_ran_new_exten = -1
                        break
                    else:
                        print(tools.centralize_message('\n\nEntrada invalida!'))
                        time.sleep(2)
                        continue
            else:
                print(tools.centralize_message('\n\nRamal Invalido!'))
                time.sleep(2)
                continue
        return self.man_add_ran_template

    def auto_add_range(self, template, ticket_voztotal):

        """Inserts extensions found automatically in the txt file"""

        self.auto_add_ran_template = template
        self.auto_add_ran_ticket_voztotal = ticket_voztotal
        while self.auto_add_ran_new_exten != -1:
            self.auto_add_ran_exten = tools.search_in_ticket(
                self.facilities.os_voip_auto_add_ran_tag + str(self.auto_add_ran_new_exten) + ':',
                self.auto_add_ran_ticket_voztotal, self.facilities.os_voip_auto_add_ran_pattert)
            if self.auto_add_ran_exten is not None:
                self.auto_add_ran_exten = self.auto_add_ran_exten[1:]
                self.auto_add_ran_check = tools.validate_range_extension(self.auto_add_ran_exten)
                if self.auto_add_ran_check:
                    self.auto_add_ran_template = tools.run_range_extension(self.facilities.os_voip_auto_add_ran_tag2,
                                                                           self.auto_add_ran_new_exten,
                                                                           self.auto_add_ran_exten,
                                                                           self.auto_add_ran_template)
                    self.auto_add_ran_new_exten += 1
            else:
                self.auto_add_ran_new_exten = -1
        return self.auto_add_ran_template

    def man_add_key(self, template):

        """Inserts the key extension provided by the user in the default template."""

        self.man_add_key_template = template
        os.system('cls')
        self.man_add_key_exten = input(
            tools.centralize_message(main.banner + '\nDigite numero chave:  Ex.\t1935544900\n') + '\n\n Chave > ')
        self.man_add_key_check = tools.validate_range_extension(self.man_add_key_exten)
        if self.man_add_key_check:
            self.man_add_key_template = tools.run_key_extension(self.facilities.os_voip_man_add_key_tag,
                                                                self.man_add_key_exten, self.man_add_key_template)
        return self.man_add_key_template

    def auto_add_key(self, template, ticket_voztotal):

        """Inserts extensions found automatically in the txt file"""

        self.auto_add_key_template = template
        self.auto_add_key_ticket_voztotal = ticket_voztotal
        self.auto_add_key_exten = tools.search_in_ticket(self.facilities.os_voip_auto_add_key_tag,
                                                         self.auto_add_key_ticket_voztotal,
                                                         self.facilities.os_voip_auto_add_key_pattert)
        if self.auto_add_key_exten is not None:
            self.auto_add_key_exten = self.auto_add_key_exten[1:]
            self.auto_add_key_check = tools.validate_range_extension(self.auto_add_key_exten)
            if self.auto_add_key_check:
                self.auto_add_key_template = tools.run_range_extension(self.facilities.os_voip_auto_add_key_tag2,
                                                                       self.auto_add_key_new_exten,
                                                                       self.auto_add_key_exten,
                                                                       self.auto_add_key_template)
        else:
            self.auto_add_key_template = self.man_add_key(self.auto_add_key_template)
        return self.auto_add_key_template

    def billing_voip(self, billing, template, ticket_voztotal):

        """Defines which type of signaling will be configured and calls the functions of entering extensions."""

        self.bi_billing_voip = billing
        self.bi_template_voip = template
        self.bi_ticket_voztotal = ticket_voztotal

        for self.bi_string_voip in self.bi_template_voip:
            self.bi_occurrence_voip += 1

        while True:
            if self.bi_billing_voip is None:
                os.system('cls')
                self.bi_billing_voip = input(tools.centralize_message(main.banner +
                                                                      '\n\n\nEscolha a bilhetagem:'
                                                                      '\n\n1-Ramal\n2-Chave') + '\n\n Bilhetagem > ')
                if self.bi_billing_voip == '1':
                    self.facilities.os_voip_extension_tag += str(self.bi_new_extension) + ': '
                    if self.bi_ticket_voztotal is None:
                        self.bi_billing_extension = None
                    else:
                        self.bi_billing_extension = tools.search_in_ticket(self.facilities.os_voip_billing_tag2,
                                                                           self.bi_ticket_voztotal,
                                                                           self.facilities.os_voip_extension_pattern)
                    if self.bi_billing_extension is not None:
                        self.bi_template_voip = self.auto_add_range(self.bi_template_voip, self.bi_ticket_voztotal)
                        return self.bi_template_voip
                    else:
                        self.bi_template_voip = self.man_add_range(self.bi_template_voip)
                        return self.bi_template_voip

                elif self.bi_billing_voip == '2':
                    if self.bi_ticket_voztotal is None:
                        self.bi_billing_extension = None
                    else:
                        self.bi_billing_extension = tools.search_in_ticket(self.facilities.os_voip_billing_tag2,
                                                                           self.bi_ticket_voztotal,
                                                                           self.facilities.os_voip_extension_pattern)
                    if self.bi_billing_extension is not None:
                        self.bi_template_voip = self.auto_add_key(self.bi_template_voip, self.bi_ticket_voztotal)
                    else:
                        self.bi_template_voip = self.man_add_key(self.bi_template_voip)
                        return self.bi_template_voip
                else:
                    print(tools.centralize_message('\n\nEntrada Invalida!'))
                    time.sleep(2)
            else:
                if self.bi_billing_voip == 'Rml':
                    self.facilities.os_voip_extension_tag += str(self.bi_new_extension) + ': '
                    if self.bi_ticket_voztotal is None:
                        self.bi_billing_extension = None
                    else:
                        self.bi_billing_extension = tools.search_in_ticket(self.facilities.os_voip_extension_tag,
                                                                           self.bi_ticket_voztotal,
                                                                           self.facilities.os_voip_extension_pattern)
                    if self.bi_billing_extension is not None:
                        self.bi_template_voip = self.auto_add_range(self.bi_template_voip, self.bi_ticket_voztotal)
                        return self.bi_template_voip
                    else:
                        self.bi_template_voip = self.man_add_range(self.bi_template_voip)
                        return self.bi_template_voip
                elif self.bi_billing_voip == 'Chve':
                    self.bi_template_voip = self.auto_add_key(self.bi_template_voip, self.bi_ticket_voztotal)
                    return self.bi_template_voip
                else:
                    self.bi_billing_voip = None
                    continue

    def audio_internet_voz_r2(self):

        """Search the network or local folder for the default configuration template for the 'Internet Link + Voz Total'
         service."""

        try:
            # self.ivr2_archive = open(main.path + 'Audiocodes\\Audiocodes_Internet_Voz_R2.txt')
            # Search for the default configuration on the server

            # self.audio_ivr2_archive = open('C:\\Users\\Public\\Documents\\Audiocodes_Internet_Voz_R2.txt')
            # Search for the default local configuration template

            self.audio_ivr2_archive = open('configuration_template - Audiocodes_M500_Internet+Voz.txt')
            # Search the configuration pattern in the same application folder

            self.audio_ivr2_template = list(self.audio_ivr2_archive.readlines())
        except TypeError:
            print(tools.centralize_message('\n\nTemplate Não Localizado!'))
            time.sleep(2)

        if self.prod_tickets is None:
            self.audio_ivr2_internet_link = None
            self.audio_ivr2_voz_total = None
            self.audio_ivr2_ponto_de_acesso = None
        else:
            self.audio_ivr2_internet_link = self.prod_tickets['Internet Link']
            self.audio_ivr2_voz_total = self.prod_tickets['Voz Total']
            self.audio_ivr2_ponto_de_acesso = self.prod_tickets['Ponto de Acesso']

            # HOSTNAME
            self.audio_ivr2_hostname = tools.search_in_ticket(self.facilities.os_host_tag,
                                                              self.audio_ivr2_ponto_de_acesso,
                                                              self.facilities.os_host_pattern)

            # CIRCUITO DE INTERNET
            self.audio_ivr2_inter_circuit = tools.search_in_ticket(self.facilities.os_inter_circ_tag,
                                                                   self.audio_ivr2_internet_link,
                                                                   self.facilities.os_inter_circ_pattern)

            # VLAN DE INTERNET
            self.audio_ivr2_inter_vlan = tools.search_in_ticket(self.facilities.os_inter_vlan_tag,
                                                                self.audio_ivr2_internet_link,
                                                                self.facilities.os_inter_vlan_pattern)

            # WAN DE INTERNET
            self.audio_ivr2_inter_wan = tools.search_in_ticket(self.facilities.os_inter_wan_tag,
                                                               self.audio_ivr2_internet_link,
                                                               self.facilities.os_inter_wan_pattern)
            # LAN DE INTERNET
            self.audio_ivr2_inter_lan = tools.search_in_ticket(self.facilities.os_inter_lan_tag,
                                                               self.audio_ivr2_internet_link,
                                                               self.facilities.os_inter_lan_pattern)
            # VELOCIDADE DE INTERNET
            self.audio_ivr2_inter_speed = tools.search_in_ticket(self.facilities.os_inter_speed_tag,
                                                                 self.audio_ivr2_internet_link,
                                                                 self.facilities.os_inter_speed_pattern)

            # CIRCUITO DE VOIP
            self.audio_ivr2_voip_circuit = tools.search_in_ticket(self.facilities.os_voip_circ_tag,
                                                                  self.audio_ivr2_voz_total,
                                                                  self.facilities.os_voip_circ_pattern)

            # VLAN DE VOIP
            self.audio_ivr2_voip_vlan = tools.search_in_ticket(self.facilities.os_voip_vlan_tag,
                                                               self.audio_ivr2_voz_total,
                                                               self.facilities.os_voip_vlan_pattern)

            # WAN DE VOIP
            self.audio_ivr2_voip_wan = tools.search_in_ticket(self.facilities.os_voip_wan_tag,
                                                              self.audio_ivr2_voz_total,
                                                              self.facilities.os_voip_wan_pattern)

            # CANAIS DE VOIP
            self.audio_ivr2_voip_channel = tools.search_in_ticket(self.facilities.os_voip_channel_tag,
                                                                  self.audio_ivr2_voz_total,
                                                                  self.facilities.os_voip_channel_pattern)

            # SBC DE VOIP
            self.audio_ivr2_voip_sbc = tools.search_in_ticket(self.facilities.os_voip_sbc_tag,
                                                              self.audio_ivr2_voz_total,
                                                              self.facilities.os_voip_sbc_pattern)

            # BILHETAGEM DE VOIP
            self.audio_ivr2_voip_billing = tools.search_in_ticket(self.facilities.os_voip_billing_tag,
                                                                  self.audio_ivr2_voz_total,
                                                                  self.facilities.os_voip_billing_pattern)

        # HOSTNAME
        self.audio_ivr2_template = self.hostname(self.audio_ivr2_hostname, self.audio_ivr2_template)

        # CIRCUITO DE INTERNET
        self.audio_ivr2_template = self.circuit_inter(self.audio_ivr2_inter_circuit, self.audio_ivr2_template)

        # VLAN DE INTERNET
        self.audio_ivr2_template = self.vlan_inter(self.audio_ivr2_inter_vlan, self.audio_ivr2_template)

        # WAN DE INTERNET
        self.audio_ivr2_template = self.wan_inter(self.audio_ivr2_inter_wan, self.audio_ivr2_template)

        # LAN DE INTERNET
        self.audio_ivr2_template = self.lan_inter(self.audio_ivr2_inter_lan, self.audio_ivr2_template)

        # VELOCIDADE DE INTERNET
        self.audio_ivr2_template = self.speed_inter(self.audio_ivr2_inter_speed, self.audio_ivr2_template)

        # CIRCUITO DE VOIP
        self.audio_ivr2_template = self.circuit_voip(self.audio_ivr2_voip_circuit, self.audio_ivr2_template)

        # VLAN DE VOIP
        self.audio_ivr2_template = self.vlan_voip(self.audio_ivr2_voip_vlan, self.audio_ivr2_template)

        # WAN DE VOIP
        self.audio_ivr2_template = self.wan_voip(self.audio_ivr2_voip_wan, self.audio_ivr2_template)

        # CANAIS DE VOIP
        self.audio_ivr2_template = self.channel_voip(self.audio_ivr2_voip_channel, self.audio_ivr2_template)

        # SBC DE VOIP
        self.audio_ivr2_template = self.sbc_voip(self.audio_ivr2_voip_sbc, self.audio_ivr2_template)

        # BILHETAGEM DE VOIP
        self.billing_voip(self.audio_ivr2_voip_billing, self.audio_ivr2_template, self.audio_ivr2_voz_total)

        return self.audio_ivr2_template

    def generate_script(self):

        """Identifies the type of service and calls the corresponding function to generate the script."""

        if self.prod_equipment == 'Audiocodes':
            if self.prod_product == 'Internet Link + Voz Total R2':
                self.gener_template = self.audio_internet_voz_r2()
                return self.gener_template


class Support:

    """This Class is responsible for check hardware and software."""

    def __init__(self, product, equipment):

        self.supp_product = product
        self.supp_equipment = equipment
        self.supp_audi_products = 'Internet Link', 'Voz Total R2', 'Voz Total ISDN', 'Voz Total PABX IP', \
                                  'Internet Link + Voz Total R2', 'VPN IP', 'VPN IP + Voz Total R2', \
                                  'VPN IP + Voz Total ISDN', 'VPN IP + Voz Total PABX IP'
        self.supp_veri_check = False

    def audiocodes(self):

        """Identifies whether the equipment informed supports the product."""

        if self.supp_product in self.supp_audi_products:
            return True

    def verify(self):

        """Identifies whether it is an equipment supported by the system."""

        if self.supp_equipment == 'Audiocodes':
            self.supp_veri_check = self.audiocodes()
            if self.supp_veri_check:
                return True
        else:
            return False


class RunAudiocodes:

    """This class manages and sends commands to the 'AudioCodes' router.'"""

    def __init__(self):

        self.audio_check_server_console = ''
        self.audio_check_server_lines = 0
        self.audio_check_server_commands = [
            'configure data',
            'interface vlan 1',
            'no service dhcp',
            'ip address dhcp',
            'ip dhcp-client default-route',
            'exit',
            'exit']
        self.audio_check_server_prompt = ''

        self.audio_update_check = False
        self.audio_update_console = ''
        self.audio_update_console = ''
        self.audio_update_prompt = ''

        self.audio_update_brtons_console = ''
        self.audio_update_brtons_prompt = ''

        self.audio_update_castable_console = ''
        self.audio_update_castable_prompt = ''

        self.audio_update_cmp_firmware = 'M500_MSBR_SIP_F6.80A.286.002.cmp'

        self.audio_check_version_console = ''
        self.audio_check_version_prompt = ''
        self.audio_check_version_router = False

        self.audio_check_rou_data_bytes = b''
        self.audio_check_rou_cmd = '\n'
        self.audio_check_rou_prompt = ''
        self.audio_check_rou_console = ''
        self.audio_check_rou_cont = 0

        self.audio_check_log_console = ''
        self.audio_check_log_prompt = ''

        self.audio_logout_console = ''

        self.audio_login_console = ''
        self.audio_login_cont = 0
        self.audio_login_status = False
        self.audio_login_prompt = ''
        self.audio_login_username = 'Admin'
        self.audio_login_password = 'Admin'

        self.audio_serial_template = []
        self.audio_serial_console = ''
        self.audio_serial_check_router = False
        self.audio_serial_check_version = False

        self.audio_configure_console = ''
        self.audio_configure_front = ''
        self.audio_configure_up = 1
        self.audio_configure_template = []
        self.audio_configure_lines = 0
        self.audio_configure_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_configure_log = []
        self.audio_configure_dot = ''

        self.audio_read_serial_console = ''
        self.audio_read_data_bytes = b''
        self.audio_read_prompt = b''
        self.audio_read_log = []

        self.audio_send_comm_console = ''
        self.audio_send_comm_cmd = ''

        self.audio_conect_config_com = 0
        self.audio_conect_console = ''

    def audio_read_serial(self, console):

        """This method reads the messages sent by the router in bytes, is converted and stored to
        check and log"""

        self.audio_read_serial_console = console

        self.audio_read_data_bytes = self.audio_read_serial_console.inWaiting()

        if self.audio_read_data_bytes:
            # print(self.audio_read_data_bytes)
            self.audio_read_prompt = self.audio_read_serial_console.read(self.audio_read_data_bytes)
            self.audio_read_log.append(str(self.audio_read_prompt) + '\n')
            '''with open('Audiocodes.txt', 'w') as self.audio_read_archive:
                self.audio_read_archive.writelines(self.audio_read_log)'''
            time.sleep(0.5)
            # print(self.audio_read_prompt)
            return self.audio_read_prompt
        else:
            return ''

    def audio_send_command(self, console, cmd=''):

        """This method sends a string-encoded string to the serial and returns the log that was generated by the method
           'read_serial'.'"""

        self.audio_send_comm_console = console
        self.audio_send_comm_cmd = cmd

        self.audio_send_comm_console.write(self.audio_send_comm_cmd.encode() + str.encode('\n'))
        time.sleep(1)
        return self.audio_read_serial(self.audio_send_comm_console)

    def audio_check_logged_in(self, console):

        """This method sends line breaks as a command to serial and reads the log that returns true
        if the router is in 'enable'"""

        self.audio_check_log_console = console

        self.audio_check_log_prompt = str(self.audio_send_command(self.audio_check_log_console, cmd='\n'))
        time.sleep(1)
        if '#' in self.audio_check_log_prompt:
            return True
        else:
            return False
        pass

    def audio_logout(self, console):

        """This method uses 'check_logged_in' to check the access status of the router and sends the 'exit'
        while the router is not prompting for User and Password"""

        self.audio_logout_console = console

        # print(tools.centralize_message('\nRealizando Logout! Aguarde...'))
        while self.audio_check_logged_in(self.audio_logout_console):
            self.audio_send_command(self.audio_logout_console, cmd='exit')
            time.sleep(.5)
        pass
        # print(tools.centralize_message('\nRealizado Logout com Sucesso!\n'))

    def audio_login(self, console):

        """This method uses 'check_logged_in' to check the status of the router and sends the user and
        password by accessing configuration mode"""

        self.audio_login_console = console

        self.audio_login_status = self.audio_check_logged_in(self.audio_login_console)
        if self.audio_login_status:
            # print(tools.centralize_message('\nJá Logado!'))
            return None

        # print(tools.centralize_message('\nRealizando Login! Aguarde...'))
        while True:
            self.audio_login_prompt = str(self.audio_send_command(console, cmd='\n'))
            if 'Username' in self.audio_login_prompt:
                self.audio_login_prompt = str(
                    self.audio_send_command(self.audio_login_console, self.audio_login_username))
                time.sleep(1)
                self.audio_login_prompt = str(
                    self.audio_send_command(self.audio_login_console, self.audio_login_password))
                time.sleep(1)
                if 'Access denied' in self.audio_login_prompt:
                    self.audio_login_cont += 1
            else:
                pass
            pass
            self.audio_login_prompt = str(self.audio_send_command(self.audio_login_console, cmd='\n'))
            time.sleep(1)
            if '>' in self.audio_login_prompt:
                self.audio_login_prompt = str(self.audio_send_command(self.audio_login_console, cmd='enable'))
                time.sleep(1)
                self.audio_login_prompt = str(
                    self.audio_send_command(self.audio_login_console, self.audio_login_password))
                time.sleep(1)
                if 'Access denied' in self.audio_login_prompt:
                    self.audio_login_cont += 1
            else:
                pass
            pass
            self.audio_login_status = self.audio_check_logged_in(self.audio_login_console)
            if self.audio_login_status:
                # print(tools.centralize_message('\nLogin Realizado!'))
                time.sleep(2)
                break
            elif self.audio_login_cont == 5:
                os.system('cls')
                input(tools.centralize_message(main.banner + '\nRoteador Inacessível!'))
                sys.exit()
            pass
        pass

    def audio_conect_com(self):

        """Performs the configuration of the COM serial communication port."""

        while True:
            os.system('cls')
            self.audio_conect_config_com = input(
                tools.centralize_message(main.banner + '\n\n\nDIGITE PORTA COM: \tEx. 3:') + '\n\n\n COM > ')
            if self.audio_conect_config_com.isnumeric():
                try:
                    self.audio_conect_console = serial.Serial(port='COM' + self.audio_conect_config_com,
                                                              baudrate=115200, parity="N", stopbits=1, bytesize=8,
                                                              timeout=8)
                except BaseException:
                    print(tools.centralize_message('\n\nPorta COM Indisponível!'))
                    time.sleep(2)
                    continue
                if self.audio_conect_console.isOpen():
                    print(tools.centralize_message('Porta COM' + self.audio_conect_config_com + ' Conectada!\n'))
                    time.sleep(2)
                    self.audio_send_command(self.audio_conect_console, cmd='\n')
                    return self.audio_conect_console
                else:
                    print(tools.centralize_message('\n\nPorta COM Indisponivel: ' + self.audio_conect_config_com))
                    time.sleep(2)
                    continue

    def audio_check_router(self, console):

        """It sends line breaks and reads the number of bytes that were returned from the serial, in the case of
           Serial return '0' The machine may be missing, more than 16 bytes it is starting or with firmware bug"""

        self.audio_check_rou_console = console
        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nVerificando Equipamento! Aguarde...'))

        while True:
            self.audio_check_rou_console.write(self.audio_check_rou_cmd.encode())
            time.sleep(5)
            self.audio_check_rou_data_bytes = self.audio_check_rou_console.inWaiting()
            if self.audio_check_rou_data_bytes == 26:
                self.audio_check_rou_prompt = str(self.audio_send_command(self.audio_check_rou_console, cmd='\n'))
                if 'Mediant 500 - MSBR>' in self.audio_check_rou_prompt or 'Mediant 500 - MSBR#' \
                        in self.audio_check_rou_prompt:
                    return True
                else:
                    continue
            elif self.audio_check_rou_data_bytes == 0 or self.audio_check_rou_data_bytes > 16:
                if self.audio_check_rou_cont < 24:
                    time.sleep(5)
                    self.audio_send_command(self.audio_check_rou_console, cmd='exit\n')
                    self.audio_check_rou_cont += 1

                    continue
                else:
                    os.system('cls')
                    print(tools.centralize_message(main.banner + '\n\nEquipamento sem acesso, verifique!'))
                    time.sleep(2)
                    self.audio_read_serial(self.audio_conect_console)
                    return False
            else:
                self.audio_check_rou_prompt = str(self.audio_send_command(self.audio_conect_console, cmd='\n'))
                if 'Username' in self.audio_check_rou_prompt or 'Mediant 500 - MSBR>' in self.audio_check_rou_prompt \
                        or 'Mediant 500 - MSBR#' in self.audio_check_rou_prompt:
                    return True
                else:
                    continue

    def audio_check_version(self, console):

        """This method performs the verification of the firmware version of the router."""

        self.audio_check_version_console = console

        self.audio_logout(self.audio_check_version_console)
        self.audio_login(self.audio_check_version_console)
        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nVerificando Atualização! Aguarde...'))
        self.audio_check_version_prompt = str(
            self.audio_send_command(self.audio_check_version_console, cmd='show system version'))
        time.sleep(2)
        self.audio_check_version_prompt += str(self.audio_send_command(self.audio_check_version_console, cmd=' '))
        time.sleep(1)

        if 'Software Version: 6.80A.286.002' in self.audio_check_version_prompt:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\n\nRoteador já está Atualizado!'))
            time.sleep(2)
            return True
        else:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\n\nRoteador Desatualizado!'))
            time.sleep(2)
            return False

    def audio_check_server(self, console):

        """Performs network testing to ensure access to the remote server."""

        self.audio_check_server_console = console

        self.audio_check_server_lines = int((len(self.audio_check_server_commands)))
        for self.audio_check_server_string in range(0, self.audio_check_server_lines):
            self.audio_send_command(self.audio_check_server_console,
                                    cmd=self.audio_check_server_commands[self.audio_check_server_string])
        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\nVerificando Servidor TFTP! Aguarde...'))
        self.audio_send_command(self.audio_check_server_console, cmd='ping ' + main.path_server + '\n')
        time.sleep(5)
        self.audio_check_server_prompt = str(self.audio_read_serial(self.audio_check_server_console))
        if '4 packets transmitted, 0 packets received' in self.audio_check_server_prompt \
                or 'hostname resolution failed' in self.audio_check_server_prompt:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\nServidor TFTP Indisponível, Verifique Ponto de Rede'))
            time.sleep(2)
            return False
        elif 'Reply from ' + main.path_server in self.audio_check_server_prompt:
            print(tools.centralize_message('\n\nServidor TFTP OK!'))
            time.sleep(2)
            return True

    def audio_update_brtons(self, console):

        """Sends commands to update the 'brtons' file."""

        self.audio_update_brtons_console = console

        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nAtualizando... br_tons_Mediant_5.6_to_6.8.dat'))
        '''self.audio_send_command(console, cmd='copy call-progress-tones from TFTP://' + main.path_server 
                                             + '/br_tons_Mediant_5.6_to_6.8.dat')'''
        self.audio_send_command(console, cmd='copy call-progress-tones from TFTP://' + main.local_host
                                             + '/br_tons_Mediant_5.6_to_6.8.dat')
        time.sleep(10)
        self.audio_update_brtons_prompt = str(self.audio_read_serial(self.audio_update_brtons_console))
        if 'Erro' in self.audio_update_brtons_prompt:
            input(tools.centralize_message('\nVerifique cabo de rede/servidor TFTP\nPress ENTER...\n'))
            self.audio_login(self.audio_update_brtons_console)
        else:
            while True:
                if 'write' in self.audio_update_brtons_prompt:
                    break
                else:
                    self.audio_update_brtons_prompt = (
                        self.audio_send_command(self.audio_update_brtons_console, cmd='\n'))
                    time.sleep(2)
                    continue

    def audio_update_castable(self, console):

        """Sends commands to update the 'castable' file."""

        self.audio_update_castable_console = console

        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nAtualizando... R2_BR_ANI_2s_DPLN_DA_RX_No_Sus_v3.dat'))
        '''self.audio_send_command(self.audio_update_castable_console, 
                                cmd='copy cas-table from TFTP://' 
                                    + main.path_server + '/R2_BR_ANI_2s_DPLN_DA_RX_No_Sus_v3.dat')'''
        self.audio_send_command(self.audio_update_castable_console, cmd='copy cas-table from TFTP://'
                                                                        + main.local_host
                                                                        + '/R2_BR_ANI_2s_DPLN_DA_RX_No_Sus_v3.dat')
        time.sleep(10)
        self.audio_update_castable_prompt = str(self.audio_read_serial(self.audio_update_castable_console))
        if 'Erro' in self.audio_update_castable_prompt:
            input(tools.centralize_message('\n\n\nVerifique cabo de rede/servidor TFTP\nPress ENTER...'))
            self.audio_login(self.audio_update_castable_console)
            return False
        else:
            while True:
                if 'write' in self.audio_update_castable_prompt:
                    return True
                else:
                    self.audio_update_castable_prompt = str(
                        self.audio_send_command(self.audio_update_castable_console, cmd='\n'))
                    time.sleep(2)

    def audio_log_copy(self):

        """Message to user during upgrade."""

        self.audio_log_copy_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_log_copy_string = '\nAtualizando:  ' + self.audio_update_cmp_firmware
        for self.audio_log_copy_up in range(0, 7):
            self.audio_log_copy_dot = '.'
            if self.audio_log_copy_up == 7:
                self.audio_log_copy_dot = ''
            self.audio_log_copy_dot *= self.audio_log_copy_up
            for self.audio_log_copy_update in self.audio_log_copy_lista:
                os.system('cls')
                print(tools.centralize_message(
                    main.banner + self.audio_log_copy_string + '\n\nCopiando firmware'
                    + self.audio_log_copy_dot + self.audio_log_copy_update))
                time.sleep(.2)

    def audio_log_save(self):

        """Message to user during upgrade."""

        self.audio_log_save_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_log_save_string = '\nAtualizando:  ' + self.audio_update_cmp_firmware
        for self.audio_log_save_up in range(0, 7):
            self.audio_log_save_dot = '.'
            if self.audio_log_save_up == 7:
                self.audio_log_save_dot = ''
            self.audio_log_save_dot *= self.audio_log_save_up
            for self.audio_log_save_update in self.audio_log_save_lista:
                os.system('cls')
                print(tools.centralize_message(
                    main.banner + self.audio_log_save_string + '\n\nSalvando firmware' + self.audio_log_save_dot
                    + self.audio_log_save_update))
                time.sleep(.2)

    def audio_log_restart(self):

        """Message to user during upgrade."""

        self.audio_log_restart_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_log_restart_string = '\nAtualizando:  ' + self.audio_update_cmp_firmware
        for self.audio_log_restart_up in range(0, 7):
            self.audio_log_restart_dot = '.'
            if self.audio_log_restart_up == 7:
                self.audio_log_restart_dot = ''
            self.audio_log_restart_dot *= self.audio_log_restart_up
            for self.audio_log_restart_update in self.audio_log_restart_lista:
                os.system('cls')
                print(tools.centralize_message(
                    main.banner + self.audio_log_restart_string + '\n\nReiniciando' + self.audio_log_restart_dot
                    + self.audio_log_restart_update))
                time.sleep(.2)

    def audio_update_cmp(self, console):

        """Sends commands to update the 'cmp' file."""

        self.audio_update_cmp_console = console

        os.system('cls')
        print(tools.centralize_message(main.banner + '\nVerificando...  ' + self.audio_update_cmp_firmware + '\n'))
        '''self.audio_send_command(self.audio_update_cmp_console, cmd='copy firmware from TFTP://' + main.path_server 
                                                                   + '/' + self.audio_update_cmp_firmware)'''
        self.audio_send_command(self.audio_update_cmp_console,
                                cmd='copy firmware from TFTP://' + main.local_host + '/'
                                    + self.audio_update_cmp_firmware)
        time.sleep(10)
        self.audio_update_cmp_prompt = str(self.audio_read_serial(self.audio_update_cmp_console))
        if 'Erro' in self.audio_update_cmp_prompt:
            input(tools.centralize_message('\nVerifique cabo de rede/servidor TFTP\nPress ENTER...'))
            self.audio_login(console)
        else:
            while True:
                self.audio_update_cmp_prompt = str(self.audio_send_command(console, cmd='\n'))
                time.sleep(1)
                if 'Username' in self.audio_update_cmp_prompt:
                    self.audio_login(console)
                    self.audio_update_cmp_login_status = self.audio_check_logged_in(console)
                    if self.audio_update_cmp_login_status:
                        self.audio_update_cmp_check = self.audio_check_version(console)
                        if self.audio_update_cmp_check:
                            break
                        else:
                            # print('\nVersion checked')
                            continue
                        pass
                    else:
                        # print('\Login checked')
                        continue
                else:
                    while True:
                        prompt = str(self.audio_send_command(console, cmd='\n'))
                        if 'Processing firmware' in prompt:
                            while True:
                                prompt = str(self.audio_send_command(console, cmd='\n'))
                                if 'Restarting' in prompt:
                                    while True:
                                        prompt = str(self.audio_send_command(console, cmd='\n'))
                                        if 'Username' in prompt:
                                            break
                                        else:
                                            self.audio_log_restart()
                                            os.system('cls')
                                            print(tools.centralize_message(
                                                main.banner + self.audio_log_restart_string + '\n\nReiniciando'))
                                            continue
                                elif 'Username' in prompt:
                                    break
                                else:
                                    self.audio_log_save()
                                    os.system('cls')
                                    print(tools.centralize_message(
                                        main.banner + self.audio_log_save_string + '\n\nSalvando firmware'))
                                    continue
                        elif 'Username' in prompt:
                            break
                        else:
                            self.audio_log_copy()
                            os.system('cls')
                            print(tools.centralize_message(
                                main.banner + self.audio_log_copy_string + '\n\nCopiando firmware'))
                            continue

    def audio_update_full(self, console):

        """This method performs the update call in the order of the files."""

        self.audio_update_console = console

        # self.audio_update_check = self.audio_check_server(self.audio_update_console)
        self.audio_update_check = True

        if self.audio_update_check:
            self.audio_update_brtons(self.audio_update_console)
            self.audio_update_castable(self.audio_update_console)
            self.audio_update_cmp(self.audio_update_console)

    def audio_configure(self, console, template):

        """Send commands contained in the template to the router."""

        self.audio_configure_console = console
        self.audio_configure_template = template

        os.system("cls")
        print(tools.centralize_message(main.banner + '\nIniciando Configuração! Aguarde...'))
        self.audio_configure_lines = int((len(self.audio_configure_template)))

        for self.audio_configure_cmd in range(0, self.audio_configure_lines):
            if self.audio_configure_up > 7:
                self.audio_configure_up = 1
            self.audio_configure_dot = '.'
            self.audio_configure_dot *= self.audio_configure_up
            for self.audio_configure_front in self.audio_configure_lista:
                os.system("cls")
                print(tools.centralize_message(
                    main.banner + '\n\nConfigurando' + self.audio_configure_dot + self.audio_configure_front))
                time.sleep(.05)
            self.audio_configure_log = str(self.audio_send_command(self.audio_configure_console,
                                                                   cmd=self.audio_configure_template[
                                                                       self.audio_configure_cmd]))
            if 'Invalid command' in self.audio_configure_log:
                with open('AutoScript\\logs\\Audiocodes.txt', 'w') as self.audio_configure_archive:
                    self.audio_configure_archive.writelines(self.audio_configure_log)
                break
            else:
                self.audio_configure_up += 1
            pass
        pass

    def audio_serial(self, template):

        """Performs the console connection, checks the integrity of the router, and initializes the update if necessary."""

        self.audio_serial_template = template
        self.audio_serial_console = self.audio_conect_com()
        self.audio_serial_check_router = self.audio_check_router(self.audio_serial_console)
        if self.audio_serial_check_router:
            self.audio_serial_check_version = self.audio_check_version(self.audio_serial_console)
            if not self.audio_serial_check_version:
                os.system('cls')
                self.audio_update_full(self.audio_serial_console)
            self.audio_configure(self.audio_serial_console, self.audio_serial_template)

            return True
        else:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\n\nRoteador com Defeito!'))
            time.sleep(2)
            return False


class Main(object):

    """"""

    def __init__(self):

        self.path_server = '\\\\10.107.16.153\\'  # IP do servidor de arquivos
        self.local_host = '192.168.0.3'  # IP da máquina local
        self.banner = '\n'.join('{:^80}'.format(s) for s in
                                '\n\n#################################################################################'
                                '\n\nAUTO SCRIPT'
                                '\n\n#################################################################################'
                                ''.split('\n'))
        self.menu_run = 3
        self.menu_order_id = ''
        self.menu_new_banner = ''
        self.menu_check_id = False
        self.menu_tickets_order_id = {}
        self.menu_temp = {}
        self.menu_tickets_product = {}
        self.menu_product = ''
        self.menu_equipment = ''
        self.menu_fin_product = ''
        self.menu_support = False

        self.sear_order_id = ''
        self.sear_dir = ''
        self.sear_file = ''
        self.sear_archive = ''
        self.sear_data = []
        self.sear_temp = {}

        self.dis_sign_tag = 'SINALIZAÇÃO PABX CLIENTE ='
        self.dis_sign_pattern = '[^SINALIZAÇÃO PABX CLIENTE = \t\n]'
        self.dis_sign_ticket = {}
        self.dis_sign_values = ''
        self.dis_sign_signaling = ''

        self.dis_prod_tickets = {}
        self.dis_prod_tag = 'PRODUTO = '
        self.dis_prod_pattern = '[^\n]'
        self.dis_prod_values = ''
        self.dis_prod_product = ''
        self.dis_prod_tickets_products = {}
        self.dis_prod_keys = ''

        self.tick_order_id = ''
        self.tick_product = ''
        self.tick_banner = ''

        self.dis_fin_tickets = {}
        self.dis_fin_product = ''
        self.dis_fin_string = ''
        self.dis_fin_voztotal = {}
        self.dis_fin_signaling = ''
        self.dis_fin_final_product = []

        self.dis_rout_tickets = {}
        self.dis_rout_tag = 'ROTEADOR = '
        self.dis_rout_pattern = '[^\n]'
        self.dis_rout_values = ''
        self.dis_rout_data = []
        self.dis_rout_router = ''

    def search_the_file(self, order_id):

        """Search the server for the configuration ticket number entered by the user."""

        self.sear_order_id = order_id
        try:
            # self.sear_dir = os.listdir(main.path_server + 'Bilhete_OSM')
            # Faz a leitura do nome dos arquivos no diretório do servidor

            self.sear_dir = os.listdir('C:\\Users\\Public\\Documents\\')
            for self.sear_file in self.sear_dir:
                if self.sear_order_id in self.sear_file:
                    # self.sear_archive = open(self.path_server + 'Bilhete_OSM\\' + self.sear_file, 'r')
                    # Search the file on the server

                    self.sear_archive = open('C:\\Users\\Public\\Documents\\' + self.sear_file, 'r')
                    # Search the file on the local machine

                    self.sear_data = list(self.sear_archive.readlines())
                    self.sear_temp = {self.sear_order_id: self.sear_data}
                    return self.sear_temp
            print(
                tools.centralize_message(
                    '\nBilhete_Ordem_' + self.sear_order_id + '_Acesso_LP(?).txt, Não Localizado!'))
            time.sleep(2)
            return None
        except FileNotFoundError:
            print(tools.centralize_message('\n\nServidor não Localizado!'))
            time.sleep(2)
            return None
        except OSError:
            print(tools.centralize_message('\n\nDiretório não Localizado!'))
            time.sleep(2)
            return None

    def discover_signaling(self, ticket):

        """Recebe um Dicionário com o número da OS e o conteúdo do arquivo de Voz Total"""

        self.dis_sign_ticket = ticket
        while True:
            if self.dis_sign_signaling is None:
                os.system('cls')
                self.dis_sign_signaling = input(
                    tools.centralize_message(self.banner + '\n\nESCOLHA A SINALIZAÇÃO DO PRODUTO:'
                                                           '\n\n1 - R2') + '\n\nSinalização >\t')
                if self.dis_sign_signaling == '1':
                    return 'Voz Total R2'
                else:
                    print(tools.centralize_message('\nOpção Invalida!'))
                    time.sleep(2)
                continue
            else:
                for self.dis_sign_values in self.dis_sign_ticket.values():
                    self.dis_sign_signaling = tools.search_in_ticket(self.dis_sign_tag, self.dis_sign_values,
                                                                     self.dis_sign_pattern)

                if self.dis_sign_signaling == 'R2':
                    return 'Voz Total R2'
                else:
                    continue

    def discover_the_product(self, tickets):

        """Recebe um Dicionário com os números das OSs e os conteúdos dos arquivos"""

        self.dis_prod_tickets = tickets
        for self.dis_prod_values in self.dis_prod_tickets.values():
            self.dis_prod_product = tools.search_in_ticket(self.dis_prod_tag,
                                                           self.dis_prod_values, self.dis_prod_pattern)

            self.dis_prod_product = self.dis_prod_product[10:]

        self.dis_prod_product = OS.validate_product(self, self.dis_prod_product)

        for self.dis_prod_keys in self.dis_prod_tickets_products.keys():
            if self.dis_prod_keys == self.dis_prod_product:
                print(tools.centralize_message(self.dis_prod_keys + ' + ' + self.dis_prod_product))
                raise AttributeError

        self.dis_prod_tickets_products.update({self.dis_prod_product: self.dis_prod_values})
        return self.dis_prod_tickets_products, self.dis_prod_product

    def discover_final_product(self, tickets):

        """Recebe um Dicionário com os números das OSs e os conteúdos dos arquivos"""

        self.dis_fin_tickets = tickets
        while True:
            if self.dis_fin_tickets is None:
                os.system('cls')
                self.dis_fin_product = input(tools.centralize_message(self.banner +
                                                                      '\n\n\nESCOLHA O PRODUTO:'
                                                                      '\n\n1 - Internet Link + Voz Total R2')
                                             + '\n\n\n Produto >\t')
                if self.dis_fin_product == '1':
                    return 'Internet Link + Voz Total R2'
                else:
                    print(tools.centralize_message('\n\nOpção Invalida!'))
                    time.sleep(2)
                    continue
            else:
                for self.dis_fin_string in self.dis_fin_tickets.keys():
                    if self.dis_fin_string == 'Voz Total':
                        self.dis_fin_voztotal = {self.dis_fin_string: self.dis_fin_tickets[self.dis_fin_string]}
                        self.dis_fin_signaling = self.discover_signaling(self.dis_fin_voztotal)
                        self.dis_fin_final_product.append(self.dis_fin_signaling)
                    else:
                        self.dis_fin_final_product.append(self.dis_fin_string)
                if 'Internet Link' in self.dis_fin_final_product and 'Voz Total R2' in self.dis_fin_final_product and \
                        'Ponto de Acesso' in self.dis_fin_final_product:
                    return 'Internet Link + Voz Total R2'
                else:
                    self.dis_fin_tickets = None
                    continue

    def discover_router(self, tickets):

        """Recebe um Dicionário com os números das OSs e os conteúdos dos arquivos"""

        self.dis_rout_tickets = tickets

        while True:
            if self.dis_rout_tickets is None:
                os.system('cls')
                self.dis_rout_router = input(tools.centralize_message(self.banner + '\n\n\n'
                                                                                    'ESCOLHA O MODELO DO EQUIPAMENTO:'
                                                                                    '\n\n1 - Audiocodes') + '\n\n\n '
                                                                                                            'Roteador> ')
                if self.dis_rout_router == '1':
                    return 'Audiocodes'
                else:
                    print(tools.centralize_message('\n\nOpção Invalida!'))
                    time.sleep(2)
                    continue
            else:
                for self.dis_rout_values in self.dis_rout_tickets.values():
                    self.dis_rout_router = tools.search_in_ticket(self.dis_rout_tag, self.dis_rout_values,
                                                                  self.dis_rout_pattern)
                    if self.dis_rout_router is None:
                        pass
                    elif 'Audiocodes' in self.dis_rout_router:
                        self.dis_rout_router = self.dis_rout_router[11:]
                        return self.dis_rout_router
                    else:
                        self.dis_rout_tickets = None
                        continue

    def menu(self):

        """Inicio da interação com usuário, solicita por três vezes o número da OS,
        porem pode ser interrompido por um 'Enter' após a primeira entrada"""

        while self.menu_run > 0:
            os.system('cls')
            self.menu_order_id = input(self.banner + '\n\n\n' + self.menu_new_banner + '\n\n\n OS > ')
            if self.menu_order_id == '?' or self.menu_order_id == 'h' or self.menu_order_id == 'H':
                input('\n ?,H,Help\t\tAjuda\n Enter\t\t\tInicia Execução\n I\t\t\tRetorna ao Início'
                      '\n M\t\t\tInformar Dados Manualmente\n S\t\t\tEncerra o Sistema\n')
                continue
            elif self.menu_order_id == '':
                if not self.menu_tickets_order_id:
                    print(tools.centralize_message('\n\nMínimo uma OS para Execução!'))
                    time.sleep(2)
                    continue
                else:
                    self.menu_run = 0
            elif self.menu_order_id == 'i' or self.menu_order_id == 'I':
                return 'i'
            elif self.menu_order_id == 'm' or self.menu_order_id == 'M':
                self.menu_tickets_product = None
                self.menu_order_id = False
                break
            elif self.menu_order_id == 's' or self.menu_order_id == 'S':
                sys.exit()
            else:
                self.menu_check_id = OS.validate_id(self, self.menu_order_id)
                if self.menu_check_id:
                    try:
                        self.menu_temp = self.search_the_file(self.menu_order_id)
                        # Call the function 'search_the_file ()' and pass the OS number as parameter
                        # If the return is 'None' it generates a 'TypeError'

                        self.menu_tickets_order_id.update(self.menu_temp)
                        # Stores the return from 'search_the_file ()' and a dictionary with OS numbers

                        self.menu_temp, self.menu_product = self.discover_the_product(self.menu_temp)
                        # find the product name
                        # If the product is repeated it generates an 'AttributeError'
                        # If the return is 'None' it generates a 'TypeError'

                        self.menu_tickets_product.update(self.menu_temp)
                        # Stores return from discover_the_product () and another dictionary with product names

                        self.menu_new_banner += self.menu_order_id + ': ' + self.menu_product + '   '.center(10, ' ')
                        # creates a string with the product name and OS number centering with 10 pixels of space
                        # If the return from 'discover_the_product ()' is 'None' it generates a 'TypeError'

                        self.menu_run -= 1

                    except TypeError:
                        continue
                    except AttributeError:
                        print(tools.centralize_message('\n\nCombinação de produtos Invalida!'))
                        time.sleep(2)
                        continue
        if self.menu_order_id:
            os.system('cls')
            print(self.banner + '\n\n\n' + self.menu_new_banner)
            time.sleep(2)
        self.menu_equipment = self.discover_router(self.menu_tickets_product)
        self.menu_fin_product = self.discover_final_product(self.menu_tickets_product)
        self.menu_support = Support(self.menu_fin_product, self.menu_equipment)
        if self.menu_support:
            return self.menu_tickets_product, self.menu_fin_product, self.menu_equipment


if __name__ == "__main__":

    while True:
        tools = Tools()
        main = Main()
        config = RunAudiocodes()

        tickets, product, equipment = main.menu()

        if tickets == 'i':
            continue

        if tickets:
            generate_script = Product(equipment, product, tickets)
            template = generate_script.generate_script()
        else:
            generate_script = Product(equipment, product, None)
            template = generate_script.generate_script()

        with open('Audiocodes_M500_Script.txt', 'w') as archive:
            archive.writelines(template)

        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nScript Gerado com Sucesso!'))
        time.sleep(3)

        check = config.audio_serial(template)

        if check:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\n\nRouter Configurado com Sucesso!'))
            time.sleep(3)
