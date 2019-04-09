#
# Guilherme César Da Silva <dasilvaguilhermecesar@gmail.com>
#
# AutoScript for Windows OS
#
#
import re
import os
import sys
import time
import serial  # LICENSE
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

    def __init__(self, ):

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

        """Recebe uma String e centraliza com 80 pixels de cada lado do caracter '\n' """

        self.cent_message = message
        center = '\n'.join('{:^80}'.format(s) for s in message.split('\n'))
        return center

    def validate_octets(self, ip):

        """Recebe uma string com um IPV4 e verifica se é válido"""

        self.valid_octe_ip = ip
        self.valid_octe_ip = self.valid_octe_ip.split('.')
        for self.valid_octe_int in self.valid_octe_ip:
            self.valid_octe_int = int(self.valid_octe_int)
            if 1 <= self.valid_octe_int <= 254:  # 1 menor ou igual var (var menor ou igual 254)
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

    def validate_range_ip(self, bit, qOcteto):

        """Recebe um String com o quarto octeto (Ex. 10.0.0.4/30  quarto octeto = 4) da faixa do IPV4 e uma outra
        String com o valor de bit (CIDR) da Máscara de rede (Ex. 10.0.0.4/30 CIDR = 30) e realiza uma comparação
        para identificar se a máscara está de acordo com a FAIXA DE IP informada, retorna boolean"""

        self.vali_rang_bits = int(bit)
        self.vali_rang_qOcteto = int(qOcteto)
        if self.vali_rang_bits == 30:
            self.vali_rang_step = 4  # Padrão IPV4 a máscara /30 é quebrada a cada 4 Ips
        elif self.vali_rang_bits == 29:
            self.vali_rang_step = 8  # Padrão IPV4 a máscara /29 é quebrada a cada 8 Ips
        elif self.vali_rang_bits == 28:
            self.vali_rang_step = 16  # Padrão IPV4 a máscara /28 é quebrada a cada 16 Ips
        elif self.vali_rang_bits == 27:
            self.vali_rang_step = 32  # Padrão IPV4 a máscara /27 é quebrada a cada 32 Ips
        elif self.vali_rang_bits == 26:
            self.vali_rang_step = 64  # Padrão IPV4 a máscara /26 é quebrada a cada 64 Ips
        elif self.vali_rang_bits == 25:
            self.vali_rang_step = 128  # Padrão IPV4 a máscara /25 é quebrada a cada 128 Ips
        elif self.vali_rang_bits == 24:
            self.vali_rang_step = 254  # Padrão IPV4 a máscara /24 é quebrada a cada 254 Ips
        else:
            return False
        for self.vali_rang_int in range(0, 255, self.vali_rang_step):  # Valores máximos IPV4 de 0 até 255
            self.vali_rang_bands.append(
                self.vali_rang_int)  # É criada uma lista com os valores de acordo com a máscara identificada
        if self.vali_rang_qOcteto in self.vali_rang_bands:  # Se o valor do quarto octeto estiver na lista é uma faixa de IP valida
            return True
        else:
            return False

    def calculate_network_mask(self, band):

        """Recebe uma String com uma FAIXA DE IPV4 (Ex. 192.168.0.0/24) separa o IP por octetos e bit da máscara e
         realiza os cálculos para identificar os IPs válidos e Broadcast,  retorna quatro strings, cotendo
         o primeiro IP disponível da faixa, o último IP disponível da faixa, o último IP valido atribuido como Gateway
         e o IP de Broadcast, qualquer valor identificado como invalido é retornado 'None' """

        self.calc_netw_band = band
        self.calc_netw_fOcteto, self.calc_netw_sOcteto, self.calc_netw_tOcteto, self.calc_netw_qOcteto_mask = self.calc_netw_band.split(
            '.')
        # Separa a Faixa em quatro blocos, contendo no último o valor em bits da máscara

        self.calc_netw_qOcteto, self.calc_netw_cidr = self.calc_netw_qOcteto_mask.split('/')
        # Separa o último octeto da máscara

        self.calc_netw_check = tools.validate_range_ip(self.calc_netw_cidr, self.calc_netw_qOcteto)  # Verifica se a faixa é True or False
        if self.calc_netw_check:  # Caso True
            self.calc_netw = int(self.calc_netw_qOcteto)
            if self.calc_netw_cidr == '30':
                self.calc_netw_first = str(self.calc_netw + 1)  # Primeiro IP disponível
                self.calc_netw_last = str(self.calc_netw + 2)  # Último IP disponível
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 2)  # Último IP valido, que se torna o Gateway
                self.calc_netw_broadcast = str(self.calc_netw + 3)  # Broadcast
                self.calc_netw_mask = '255.255.255.252'  # Máscara representada em decimal
            elif self.calc_netw_cidr == '29':
                self.calc_netw_first = str(self.calc_netw + 1)  # Primeiro IP disponível
                self.calc_netw_last = str(self.calc_netw + 5)  # Último IP disponível
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 6)  # Último IP valido, que se torna o Gateway
                self.calc_netw_broadcast = str(self.calc_netw + 7)  # Broadcast
                self.calc_netw_mask = '255.255.255.248'  # Máscara representada em decimal
            elif self.calc_netw_cidr == '28':
                self.calc_netw_first = str(self.calc_netw + 1)  # Primeiro IP disponível
                self.calc_netw_last = str(self.calc_netw + 13)  # Último IP disponível
                self.calc_netw_qOctetoGateway = str(self.calc_netw + 14)  # Último IP valido, que se torna o Gateway
                self.calc_netw_broadcast = str(self.calc_netw + 15)  # Broadcast
                self.calc_netw_mask = '255.255.255.240'  # Máscara representada em decimal
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
                return None  # Caso não encontre a faixa para realizar o cálculo
        else:
            return None  # Caso False
        self.calc_netw_fband = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' + self.calc_netw_first)
        self.calc_netw_lband = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' + self.calc_netw_last)
        self.calc_netw_ipGateway = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' + self.calc_netw_qOctetoGateway)
        self.calc_netw_broadcast = ''.join(
            self.calc_netw_fOcteto + '.' + self.calc_netw_sOcteto + '.' + self.calc_netw_tOcteto + '.' + self.calc_netw_broadcast)
        # Junta os octetos novamente de acordo com os cálculos

        return self.calc_netw_fband, self.calc_netw_lband, self.calc_netw_ipGateway, self.calc_netw_broadcast, self.calc_netw_mask  # Retorna os IPs cálculados

    def search_in_ticket(self, tag, data, pattern):

        """Recebe um String como um padrão de comparação para ser pesquisado dentro de um Lista que também é recebido
        como parâmetro, também é recebido um  outro padrão como String para ser aplicado sobre o resultado da pesquisa
         para realizar um filtro (limpeza) nos caracteres que serão retornados"""

        self.sear_tick_tag = tag
        self.sear_tick_data = data
        self.sear_tick_pattern = pattern
        for self.sear_tick_string in self.sear_tick_data:
            # Percorre a lista de strings procurando pelo padrão a ser encontrado
            re.search(self.sear_tick_tag, self.sear_tick_string)
            # print('Searching for "%s" in \n\n%s' % (self.sear_tick_tag, self.sear_tick_string))
            if re.search(self.sear_tick_tag, self.sear_tick_string):
                # print('\nMatch was found.')
                self.sear_tick_found = re.findall(self.sear_tick_pattern, self.sear_tick_string)
                # Caso o padrão seja encontrado é realizada uma limpeza na string
                # print(self.found)
                self.sear_tick_found = ''.join(self.sear_tick_found)
                return self.sear_tick_found
            else:
                # A pesquisa continua até o fim da lista
                # print('\nNo match was found')
                continue
            pass
        pass
        return None  # Caso não seja encontrado é retorna 'None'

    def search_in_template(self, tag, data):

        """Recebe uma tag de nome a ser pesquisado em uma lista recebida e quando encontrado é retornado o número da
        linha onde está a tag"""

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

        """Recebe uma String com o ramal ou uma gama de ramais a serem verificados,
           Ex. 1932000000 ou 1932000000^1932000099"""

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

        """Recebe uma String 'tag' que será procurada dentro do template, um contador da quantidade de ramais a serem
        configurados, um ramal já validado e o 'template' padrão de configurações. Insere no template os comandos de
        acordo com os ramais processados"""

        self.run_ran_ext_tag = tag
        self.run_ran_ext_new_extension = new_extension
        self.run_ran_ext_extension = extension
        self.run_ran_ext_template = template

        if '~' in self.run_ran_ext_extension:

            self.run_ran_ext_prefix, self.run_ran_ext_suffix = tools.compare_range(self.run_ran_ext_extension)

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'gw manipulations src-number-map-tel2ip ' + str(
                                                 self.run_ran_ext_new_extension) + '\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'src-prefix "' + self.run_ran_ext_suffix + '"\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'num-of-digits-to-leave 0\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'prefix-to-add "' + self.run_ran_ext_prefix + '"\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'activate\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'exit\n')

            self.run_ran_ext_new_extension += 1
        else:

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'gw manipulations src-number-map-tel2ip ' + str(
                                                 self.run_ran_ext_new_extension) + '\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'num-of-digits-to-leave 0\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number,
                                             'prefix-to-add "' + self.run_ran_ext_extension + '"\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'activate\n')

            self.run_ran_ext_line_number = (
                tools.search_in_template(self.run_ran_ext_tag, self.run_ran_ext_template))
            self.run_ran_ext_template.insert(self.run_ran_ext_line_number, 'exit\n')

        self.run_ran_ext_new_extension += 1
        return self.run_ran_ext_template

    def run_key_extension(self, tag, extension, template):

        """Recebe uma String 'tag' que será procurada dentro do template, um ramal já validado e o 'template' padrão
        de configurações. Insere no template os comandos de acordo com os ramais processados"""

        self.run_key_ext_tag = tag
        self.run_key_ext_extension = extension
        self.run_key_ext_template = template

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'gw manipulations src-number-map-tel2ip 0\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'num-of-digits-to-leave 0\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'prefix-to-add "' + self.run_key_ext_extension + '"\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'activate\n')

        self.run_key_ext_line_number = (tools.search_in_template(self.run_key_ext_tag, self.run_key_ext_template))
        self.run_key_ext_template.insert(self.run_key_ext_line_number, 'exit\n')

        return self.run_key_ext_template

    def compare_range(self, extensions):

        """Recebe uma String com o ramal a ser inserido no template, realiza a comparação para identificar quais os
        números variantes"""

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

        """Recebe uma String com o número da Ordem de Serviço"""

        self.id_os = id_os
        if self.id_os.isnumeric():  # Valida se é número
            self.size_id = len(self.id_os)  # Valida a quantidade de números
            if self.size_id <= 6:  # Limita a seis números
                return self.id_os  # Retorna a ordem de serviço validada
            else:
                print(tools.centralize_message('\nOrdem de Serviço tem Apenas 6 Números'))
                time.sleep(2)
        else:
            print(tools.centralize_message('\nDigite Apenas Números'))
            time.sleep(2)
            return False  # Fora do padrão esperado é retornado 'False'

    def validate_product(self, product):

        """Recebe uma String com nome do produto"""

        self.product = product
        if self.product == 'Internet Link':  # Valida qual o produto será configurado
            return 'Internet Link'
        elif self.product == 'Voz Total':
            return 'Voz Total'
        elif self.product == 'Ponto de Acesso':
            return 'Ponto de Acesso'
        else:
            return None  # Produto for a do padrão é retornado 'None'

    def validate_hostname(self, hostname):

        """Recebe uma String com o hostname do equipamento"""

        self.hostname = hostname
        self.size_host = len(self.hostname)  # identifica o tamanho do hostname
        if 15 <= self.size_host <= 30:  # Limita o tamanho entre 15 e 30 caracteres
            self.hostname = self.hostname.replace('clm-sw-', 'cl-rt-')
            return self.hostname  # Após validado é retornado o hostname
        else:
            return None  # Fora do padrão é retornado 'None'

    def validate_circuit(self, circuit):

        """Recebe uma String com o circuito de cadastro do produto"""

        self.circuit = circuit
        if self.circuit.isnumeric():  # Valida se é número
            self.size_circ = len(self.circuit)  # Valida a quantidade de números
            if self.size_circ <= 10:  # Limita a dez números
                return self.circuit  # Retorna o circuito validados
        else:
            print(main.centralize_message('\nDigite Apenas Números'))
            time.sleep(2)
            return None

    def validate_vlan(self, vlan):

        """Recebe uma String com a vlan do produto"""

        self.vlan = vlan
        if self.vlan.isnumeric():  # Valida se é número
            self.vlan = int(self.vlan)  # Converte a string em int
            if 0 < self.vlan <= 4000:  # Limita o tamanho entre 1 e 4000 caracteres
                return str(self.vlan)  # Retorna a vlan validada
            else:
                print(tools.centralize_message('\nDigite Vlan entre 1 e 4000'))
                time.sleep(2)
                return None  # Número fora do padrão de rede, retorna 'None'
        else:
            print(tools.centralize_message('\nDigite Apenas Números'))
            time.sleep(2)
            return None  # Fora do padrão é retornado 'None'

    def validate_wan(self, wan):

        """Recebe uma String com a faixa de IP a ser utilizada na WAN do equipamento"""

        self.wan = wan
        return tools.calculate_network_mask(self.wan)
        # Chama a função 'calculate_network_mask' passando a string como parâmentro

    def validate_lan(self, lan):

        """Recebe uma String com a faixa de IP a ser utilizada na LAN do equipamento"""

        self.lan = lan
        return tools.calculate_network_mask(self.lan)
        # Chama a função 'calculate_network_mask' passando a string como parâmentro

    def validate_speed(self, speed):

        """Recebe uma String com da velocidade do link"""

        self.speed = speed
        if self.speed.isnumeric():  # Valida se é número
            self.speed = int(self.speed)  # Converte a string em int
            if self.speed > 0:  # Verifica se o valor não é igual a zero
                self.speed *= 1024
                return str(self.speed)  # Retorna o número validado
            else:
                return None  # Retorna 'None' caso seja igual a zero ou negativo
        else:
            return None  # Retorna 'None' caso não seja apenas números

    def validate_signaling(self, signaling):

        """Recebe uma String com o padrão de sinalização do link, compara as sinalizações
        disponíveis e caso não encontre é retornado 'None' """

        self.signaling = signaling
        if self.signaling == 'R2':
            return 'R2'
        elif self.signaling == 'ISDN':
            return 'ISDN'

    def validate_sbc(self, sbc):

        """Recebe uma String com um IP a ser utilizada na SBC do equipamento"""

        self.sbc = sbc
        return tools.validate_octets(self.sbc)
        # Chama a função 'validate_octets()' passando a string como parâmentro

    def validate_channel(self, channel):

        """Recebe uma String com a quantidade de canais que serão configurados e faz uma verificação
        se a quantidade é compativel com o equipamento"""

        self.channel = channel
        if self.channel.isnumeric():  # Valida se é número
            self.channel = int(self.channel)  # Converte a string em int
            if 0 < self.channel <= 30:  # Limita o tamanho entre 1 e 30 caracteres
                return str(self.channel)  # Retorna a vlan validada
            else:
                print(tools.centralize_message('\nDigite Canais entre 1 e 30'))
                time.sleep(2)
                return None  # Número fora do padrão de rede, retorna 'None'
        else:
            print(tools.centralize_message('\nDigite Apenas Números'))
            time.sleep(2)
            return None  # Fora do padrão é retornado 'None'


class Product:

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
        self.sbc_template_voip = []
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

    # HOSTNAME
    def hostname(self, hostname, template):
        self.host_hostname = hostname
        self.host_template = template
        self.host_linenumber = tools.search_in_template(self.facilities.os_host_tag2, self.host_template)
        while True:
            if self.host_hostname is None:
                os.system('cls')
                self.host_hostname = input(tools.centralize_message(main.banner + '\n\n\nDIGITE HOSTNAME:'
                                                                                 '\tEx. cl-sw-cas-00001-empresa-01'
                                                                                 '') + '\n\n\n Hostname > ')
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

    # CIRCUITO DE INTERNET
    def circuit_inter(self, circuit, template):
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
                    print(tools.centralize_message('\nCircuito de Internet Link Invalido'))
                    time.sleep(2)
                    continue
                else:
                    self.circ_template_inter[self.circ_linenumber_inter] = self.circ_template_inter[self.circ_linenumber_inter].replace(self.facilities.os_inter_circ_tag2, self.circ_circuit_inter)
                    return self.circ_template_inter
            else:
                self.circ_circuit_inter = self.facilities.validate_circuit(self.circ_circuit_inter)
                self.circ_template_inter[self.circ_linenumber_inter] = self.circ_template_inter[self.circ_linenumber_inter].replace(self.facilities.os_inter_circ_tag2, self.circ_circuit_inter)
                return self.circ_template_inter

    # VLAN DE INTERNET
    def vlan_inter(self, vlan, template):
        self.vl_vlan_inter = vlan
        self.vl_template_inter = template
        for self.vl_string_inter in self.vl_template_inter:
            if self.facilities.os_inter_vlan_tag2 in self.vl_string_inter:
                self.vl_occurrence_inter += 1
        while True:
            if self.vl_vlan_inter is None:
                os.system('cls')
                self.vl_vlan_inter = input(tools.centralize_message(main.banner + '\n\n\nDigite Vlan de Internet Link:'
                                                                                 '\tEx. 10') +
                                           '\n\n\n Vlan de Internet Link > ')
                self.vl_vlan_inter = self.facilities.validate_vlan(self.vl_vlan_inter)
                if self.vl_vlan_inter is None:
                    print(tools.centralize_message('\nVlan de Internet Link Invalida'))
                    time.sleep(2)
                    continue
                else:
                    for self.vl_string_inter in range(self.vl_occurrence_inter):
                        self.vl_linenumber_inter = tools.search_in_template(self.facilities.os_inter_vlan_tag2, self.vl_template_inter)
                        self.vl_template_inter[self.vl_linenumber_inter] = self.vl_template_inter[self.vl_linenumber_inter].replace(self.facilities.os_inter_vlan_tag2, self.vl_vlan_inter)
                    return self.vl_template_inter
            else:
                self.vl_vlan_inter = self.facilities.validate_vlan(self.vl_vlan_inter)
                for self.vl_int_inter in range(self.vl_occurrence_inter):
                    self.vl_linenumber_inter = tools.search_in_template(self.facilities.os_inter_vlan_tag2, self.vl_template_inter)
                    self.vl_template_inter[self.vl_linenumber_inter] = self.vl_template_inter[self.vl_linenumber_inter].replace(self.facilities.os_inter_vlan_tag2, self.vl_vlan_inter)
                return self.vl_template_inter

    # WAN DE INTERNET
    def wan_inter(self, wan, template):
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
                self.wan_inter_wan = input(tools.centralize_message(main.banner + '\n\n\nDigite a faixa Wan de Internet Link:'
                                                                                 '\tEx. 200.125.78.28/30') +
                                           '\n\n\n Wan de Internet Link > ')
                try:
                    self.wan_inter_fband, self.wan_inter_lband, self.wan_inter_ipGateway, self.wan_inter_broadcast, self.wan_inter_mask = (self.facilities.validate_wan(self.wan_inter_wan))
                except ValueError:
                    print(tools.centralize_message('\n Entrada Invalida'))
                    time.sleep(2)
                    self.wan_inter_wan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n Faixa de Wan Invalida'))
                    time.sleep(2)
                    self.wan_inter_wan = None
                    continue
                for self.wan_inter_search in range(self.wan_inter_occurrences):
                    self.wan_inter_line_number = (tools.search_in_template(self.facilities.os_inter_wan_tag2, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag2, self.wan_inter_fband + ' ' + self.wan_inter_mask)

                for self.wan_inter_search in range(self.wan_inter_occurrences1):
                    self.wan_inter_line_number = (tools.search_in_template(self.facilities.os_inter_wan_tag3, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag3, self.wan_inter_fband)

                for self.wan_inter_search in range(self.wan_inter_occurrences2):
                    self.wan_inter_line_number = (tools.search_in_template(self.facilities.os_inter_wan_tag4, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag4, self.wan_inter_lband)
                return self.wan_inter_template
            else:
                try:
                    self.wan_inter_fband, self.wan_inter_lband, self.wan_inter_ipGateway, self.wan_inter_broadcast, self.wan_inter_mask = (
                        self.facilities.validate_wan(self.wan_inter_wan))
                except ValueError:
                    self.wan_inter_wan = None
                    continue
                except TypeError:
                    self.wan_inter_wan = None
                    continue
                for self.wan_inter_search in range(self.wan_inter_occurrences):
                    self.wan_inter_line_number = (tools.search_in_template(self.facilities.os_inter_wan_tag2, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag2, self.wan_inter_fband + ' ' + self.wan_inter_mask)

                for self.wan_inter_search in range(self.wan_inter_occurrences1):
                    self.wan_inter_line_number = (tools.search_in_template(self.facilities.os_inter_wan_tag3, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag3, self.wan_inter_fband)

                for self.wan_inter_search in range(self.wan_inter_occurrences2):
                    self.wan_inter_line_number = (tools.search_in_template(self.facilities.os_inter_wan_tag4, self.wan_inter_template))
                    self.wan_inter_template[self.wan_inter_line_number] = self.wan_inter_template[self.wan_inter_line_number].replace(self.facilities.os_inter_wan_tag4, self.wan_inter_lband)
                return self.wan_inter_template

    # LAN DE INTERNET
    def lan_inter(self, lan, template):
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
                    tools.centralize_message(main.banner + '\n\n\nDigite a faixa Lan de Internet Link:'
                                                           '\tEx. 200.125.78.24/29') +
                    '\n\n\n Lan de Internet Link > ')
                try:
                    self.lan_inter_fband, self.lan_inter_lband, self.lan_inter_ipGateway, self.lan_inter_broadcast, self.lan_inter_mask = (self.facilities.validate_lan(self.lan_inter_lan))
                except ValueError:
                    print(tools.centralize_message('\n Entrada Invalida'))
                    time.sleep(2)
                    self.lan_inter_lan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n Faixa de Lan Invalida'))
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
                    self.lan_inter_fband, self.lan_inter_lband, self.lan_inter_ipGateway, self.lan_inter_broadcast, self.lan_inter_mask = (
                        self.facilities.validate_lan(self.lan_inter_lan))
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

    # VELOCIDADE DE INTERNET
    def speed_inter(self, speed, template):
        self.speed_speed_inter = speed
        self.speed_template_inter = template

        while True:
            if self.speed_speed_inter is None:
                os.system('cls')
                self.speed_speed_inter = input(
                    tools.centralize_message(main.banner + '\n\n\nDigite Velocidade de Internet Link:'
                                                           '\tEx. 100') +
                    '\n\n\n Velocidade de Internet Link > ')
                self.speed_speed_inter = self.facilities.validate_speed(self.speed_speed_inter)
                if self.speed_speed_inter is None:
                    print(tools.centralize_message('\nVelocidade de Internet Link Invalida'))
                    time.sleep(2)
                    continue
                else:
                    self.speed_linenumber_inter = tools.search_in_template(self.facilities.os_inter_speed_tag2,
                                                                           self.speed_template_inter)
                    self.speed_template_inter[self.speed_linenumber_inter] = self.speed_template_inter[
                        self.speed_linenumber_inter].replace \
                        (self.facilities.os_inter_speed_tag2, self.speed_speed_inter)
                    return self.speed_template_inter
            else:
                self.speed_speed_inter = self.facilities.validate_speed(self.speed_speed_inter)
                self.speed_linenumber_inter = tools.search_in_template(self.facilities.os_inter_speed_tag2,
                                                                       self.speed_template_inter)
                self.speed_template_inter[self.speed_linenumber_inter] = self.speed_template_inter[
                    self.speed_linenumber_inter].replace \
                    (self.facilities.os_inter_speed_tag2, self.speed_speed_inter)
                return self.speed_template_inter

    # CIRCUITO DE VOIP
    def circuit_voip(self, circuit, template):
        self.circ_circuit_voip = circuit
        self.circ_template_voip = template
        self.circ_linenumber_voip = tools.search_in_template(self.facilities.os_voip_circ_tag2,
                                                              self.circ_template_voip)
        while True:
            if self.circ_circuit_voip is None:
                os.system('cls')
                self.circ_circuit_voip = input(
                    tools.centralize_message(main.banner + '\n\n\nDigite ID do Circuito Voz Total:'
                                                          '\tEx. 0000000002') +
                    '\n\n\n Circuito de Voz Total > ')
                self.circ_circuit_voip = self.facilities.validate_circuit(self.circ_circuit_voip)
                if self.circ_circuit_voip is None:
                    print(tools.centralize_message('\nCircuito de Voz Total Invalido'))
                    time.sleep(2)
                    continue
                else:
                    self.circ_template_voip[self.circ_linenumber_voip] = self.circ_template_voip[
                        self.circ_linenumber_voip].replace \
                        (self.facilities.os_voip_circ_tag2, self.circ_circuit_voip)
                    return self.circ_template_voip
            else:
                self.circ_circuit_voip = self.facilities.validate_circuit(self.circ_circuit_voip)
                self.circ_template_voip[self.circ_linenumber_voip] = self.circ_template_voip[
                    self.circ_linenumber_voip].replace \
                    (self.facilities.os_voip_circ_tag2, self.circ_circuit_voip)
                return self.circ_template_voip

    # VLAN DE VOIP
    def vlan_voip(self, vlan, template):
        self.vl_vlan_voip = vlan
        self.vl_template_voip = template
        for self.vl_string_voip in self.vl_template_voip:
            if self.facilities.os_voip_vlan_tag2 in self.vl_string_voip:
                self.vl_occurrence_voip += 1
        while True:
            if self.vl_vlan_voip is None:
                os.system('cls')
                self.vl_vlan_voip = input(tools.centralize_message(main.banner + '\n\n\nDigite Vlan Voz Total:'
                                                                                 '\tEx. 11') +
                                           '\n\n\n Vlan de Voz Total > ')
                self.vl_vlan_voip = self.facilities.validate_vlan(self.vl_vlan_voip)
                if self.vl_vlan_voip is None:
                    print(tools.centralize_message('\nVlan de Voz Total Invalida'))
                    time.sleep(2)
                    continue
                else:
                    for self.vl_string_voip in range(self.vl_occurrence_voip):
                        self.vl_linenumber_voip = tools.search_in_template(self.facilities.os_voip_vlan_tag2,
                                                                            self.vl_template_voip)
                        self.vl_template_voip[self.vl_linenumber_voip] = self.vl_template_voip[
                            self.vl_linenumber_voip].replace\
                            (self.facilities.os_voip_vlan_tag2, self.vl_vlan_voip)
                    return self.vl_template_voip
            else:
                self.vl_vlan_voip = self.facilities.validate_vlan(self.vl_vlan_voip)
                for self.vl_string_voip in range(self.vl_occurrence_voip):
                    self.vl_linenumber_voip = tools.search_in_template(self.facilities.os_voip_vlan_tag2,
                                                                        self.vl_template_voip)
                    self.vl_template_voip[self.vl_linenumber_voip] = self.vl_template_voip[
                        self.vl_linenumber_voip].replace\
                        (self.facilities.os_voip_vlan_tag2, self.vl_vlan_voip)
                return self.vl_template_voip

    # WAN DE VOIP
    def wan_voip(self, wan, template):
        self.wan_voip_wan = wan
        self.wan_voip_template = template

        for self.wan_voip_string in self.wan_voip_template:
            if self.facilities.os_voip_wan_tag2 in self.wan_voip_string:
                self.wan_voip_occurrences += 1

        while True:
            if self.wan_voip_wan is None:
                os.system('cls')
                self.wan_voip_wan = input(tools.centralize_message(main.banner + '\n\n\nDigite a faixa Wan de Voz Total:'
                                                                                 '\tEx. 10.55.235.180/30') +
                                           '\n\n\n Wan de Voz Total > ')
                try:
                    self.wan_voip_fband, self.wan_voip_lband, self.wan_voip_ipGateway, self.wan_voip_broadcast, self.wan_voip_mask = (
                        self.facilities.validate_wan(self.wan_voip_wan))
                except ValueError:
                    print(tools.centralize_message('\n Entrada Invalida'))
                    time.sleep(2)
                    self.wan_voip_wan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n Faixa de Wan Invalida'))
                    time.sleep(2)
                    self.wan_voip_wan = None
                    continue
                for self.wan_voip_search in range(self.wan_voip_occurrences):
                    self.wan_voip_line_number = (tools.search_in_template(self.facilities.os_voip_wan_tag2, self.wan_voip_template))
                    self.wan_voip_template[self.wan_voip_line_number] = self.wan_voip_template[self.wan_voip_line_number].replace(self.facilities.os_voip_wan_tag2, self.wan_voip_fband + ' ' + self.wan_voip_mask)
                return self.wan_voip_template
            else:
                try:
                    self.wan_voip_fband, self.wan_voip_lband, self.wan_voip_ipGateway, self.wan_voip_broadcast, self.wan_voip_mask = (
                        self.facilities.validate_wan(self.wan_voip_wan))
                except ValueError:
                    self.wan_voip_wan = None
                    continue
                except TypeError:
                    self.wan_voip_wan = None
                    continue
                for self.wan_voip_search in range(self.wan_voip_occurrences):
                    self.wan_voip_line_number = (tools.search_in_template(self.facilities.os_voip_wan_tag2, self.wan_voip_template))
                    self.wan_voip_template[self.wan_voip_line_number] = self.wan_voip_template[self.wan_voip_line_number].replace(self.facilities.os_voip_wan_tag2, self.wan_voip_fband + ' ' + self.wan_voip_mask)
                return self.wan_voip_template

    # LAN DE VOIP
    def lan_voip(self, lan, template):
        self.lan_voip_lan = lan
        self.lan_voip_template = template

        for self.lan_voip_string in self.lan_voip_template:
            if self.facilities.os_voip_lan_tag2 in self.lan_voip_string:
                self.lan_voip_occurrences += 1

        while True:
            if self.lan_voip_lan is None:
                os.system('cls')
                self.lan_voip_lan = input(
                    tools.centralize_message(main.banner + '\n\n\nDigite a faixa Lan de Voz Total:'
                                                           '\tEx. 187.22.252.232/29') +
                    '\n\n\n Lan de Voz Total > ')
                try:
                    self.lan_voip_fband, self.lan_voip_lband, self.lan_voip_ipGateway, self.lan_voip_broadcast, self.lan_voip_mask = (
                        self.facilities.validate_lan(self.lan_voip_lan))
                except ValueError:
                    print(tools.centralize_message('\n Entrada Invalida'))
                    time.sleep(2)
                    self.lan_voip_lan = None
                    continue
                except TypeError:
                    print(tools.centralize_message('\n Faixa de Lan Invalida'))
                    time.sleep(2)
                    self.lan_voip_lan = None
                    continue
                for self.lan_voip_search in range(self.lan_voip_occurrences):
                    self.lan_voip_line_number = (
                        tools.search_in_template(self.facilities.os_voip_lan_tag2, self.lan_voip_template))
                    self.lan_voip_template[self.lan_voip_line_number] = self.lan_voip_template[
                        self.lan_voip_line_number].replace(self.facilities.os_voip_lan_tag2, self.lan_voip_fband + ' ' + self.lan_voip_mask)
                return self.lan_voip_template
            else:
                try:
                    self.lan_voip_fband, self.lan_voip_lband, self.lan_voip_ipGateway, self.lan_voip_broadcast, self.lan_voip_mask = (self.facilities.validate_lan(self.lan_voip_lan))
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

    # SBC DE VOIP
    def sbc_voip(self, sbc, template):
        self.sbc_voip_sbc = sbc
        self.sbc_voip_template = template

        for self.sbc_voip_string in self.sbc_voip_template:
            if self.facilities.os_voip_sbc_tag2 in self.sbc_voip_string:
                self.sbc_occurrence_voip += 1

        while True:
            if self.sbc_voip_sbc is None:
                os.system('cls')
                self.sbc_voip_sbc = input(
                    tools.centralize_message(main.banner + '\n\n\nDigite o IP SBC de Voz Total:'
                                                           '\tEx. 172.26.154.70') +
                    '\n\n\n SBC de Voz Total > ')
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
                    self.sbc_linenumber_voip = (tools.search_in_template(self.facilities.os_voip_sbc_tag2, self.sbc_voip_template))
                    self.sbc_voip_template[self.sbc_linenumber_voip] = self.sbc_voip_template[self.sbc_linenumber_voip].replace(self.facilities.os_voip_sbc_tag2, self.sbc_voip_sbc)
            return self.sbc_voip_template

    # CANAIS DE VOIP
    def channel_voip(self, channel, template):
        self.ch_channel_voip = channel
        self.ch_template_voip = template
        for self.ch_string_voip in self.ch_template_voip:
            if self.facilities.os_voip_channel_tag2 in self.ch_string_voip:
                self.ch_occurrence_voip += 1
        while True:
            if self.ch_channel_voip is None:
                os.system('cls')
                self.ch_channel_voip = input(tools.centralize_message(main.banner + '\n\n\nDigite Canais de Voz Total:'
                                                                                 '\tEx. 30') +
                                           '\n\n\n Canais de Voz Total > ')
                self.ch_channel_voip = self.facilities.validate_channel(self.ch_channel_voip)
                if self.ch_channel_voip is None:
                    print(tools.centralize_message('\nCanais de Voz Total Invalido'))
                    time.sleep(2)
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
                    self.ch_linenumber_voip = tools.search_in_template(self.facilities.os_voip_channel_tag2, self.ch_template_voip)

                    self.ch_template_voip[self.ch_linenumber_voip] = self.ch_template_voip[
                        self.ch_linenumber_voip].replace('31', self.ch_channel_voip)
                return self.ch_template_voip

    # ADICIONA GAMA DE RAMAIS MANUALMENTE
    def man_add_range(self, template):

        """Esse método é acionado quando o roteador é configurado para bilhetagem 'RAMAL' e a pesquisa do método
        'auto_add_range' não encontrou os dados necessários no bilhete txt"""

        self.man_add_ran_template = template
        while self.man_add_ran_new_exten != -1:
            os.system('cls')
            print(tools.centralize_message(main.banner))
            self.man_add_ran_exten = input(tools.centralize_message(main.banner + '\nDigite os Ramais:\tEx. 1935544900~1935544999 ou 1935544900') + '\n\n Ramal > ')
            self.man_add_ran_check = tools.validate_range_extension(self.man_add_ran_exten)
            if self.man_add_ran_check:
                self.man_add_ran_template = tools.run_range_extension(self.facilities.os_voip_man_add_ran_tag, self.man_add_ran_new_exten, self.man_add_ran_exten, self.man_add_ran_template)
                while True:
                    os.system('cls')
                    print(tools.centralize_message(main.banner))
                    self.man_add_ran_add = input(tools.centralize_message('\nAdicionar uma outra gama de ramais?') + "\n\n'S' ou 'N' > ")
                    if self.man_add_ran_add == 's' or self.man_add_ran_add == 'S':
                        break
                    elif self.man_add_ran_add == 'n' or self.man_add_ran_add == 'N':
                        self.man_add_ran_new_exten = -1
                        break
                    else:
                        print(tools.centralize_message('\nEntrada invalida!'))
                        time.sleep(2)
                        continue
            else:
                print(tools.centralize_message('\nRamal Invalido!'))
                time.sleep(2)
                continue
        return self.man_add_ran_template

    # ADICIONA GAMA DE RAMAIS AUTOMATICO
    def auto_add_range(self, template, ticket_voztotal):
        self.auto_add_ran_template = template
        self.auto_add_ran_ticket_voztotal = ticket_voztotal
        while self.auto_add_ran_new_exten != -1:
            self.auto_add_ran_exten = tools.search_in_ticket(self.facilities.os_voip_auto_add_ran_tag + str(self.auto_add_ran_new_exten) + ':', self.auto_add_ran_ticket_voztotal, self.facilities.os_voip_auto_add_ran_pattert)
            if self.auto_add_ran_exten is not None:
                self.auto_add_ran_exten = self.auto_add_ran_exten[1:]
                self.auto_add_ran_check = tools.validate_range_extension(self.auto_add_ran_exten)
                if self.auto_add_ran_check:
                    self.auto_add_ran_template = tools.run_range_extension(self.facilities.os_voip_auto_add_ran_tag2, self.auto_add_ran_new_exten, self.auto_add_ran_exten, self.auto_add_ran_template)
                    self.auto_add_ran_new_exten += 1
            else:
                self.auto_add_ran_new_exten = -1
        return self.auto_add_ran_template

    # ADICIONA RAMAL CHAVE MANUALMENTE
    def man_add_key(self, template):
        self.man_add_key_template = template
        os.system('cls')
        print(tools.centralize_message(main.banner))
        self.man_add_key_exten = input(tools.centralize_message(main.banner + '\nDigite numero chave:  Ex.\t1935544900\n') + '\n\n Chave > ')
        self.man_add_key_check = tools.validate_range_extension(self.man_add_key_exten)
        if self.man_add_key_check:
            self.man_add_key_template = tools.run_key_extension(self.facilities.os_voip_man_add_key_tag, self.man_add_key_exten, self.man_add_key_template)
        return self.man_add_key_template

    # ADICIONA RAMAL CHAVE AUTOMATICO
    def auto_add_key(self, template, ticket_voztotal):
        self.auto_add_key_template = template
        self.auto_add_key_ticket_voztotal = ticket_voztotal
        self.auto_add_key_exten = tools.search_in_ticket(self.facilities.os_voip_auto_add_key_tag, self.auto_add_key_ticket_voztotal, self.facilities.os_voip_auto_add_key_pattert)
        if self.auto_add_key_exten is not None:
            self.auto_add_key_exten = self.auto_add_key_exten[1:]
            self.auto_add_key_check = tools.validate_range_extension(self.auto_add_key_exten)
            if self.auto_add_key_check:
                self.auto_add_key_template = tools.run_range_extension(self.facilities.os_voip_auto_add_key_tag2, self.auto_add_key_new_exten, self.auto_add_key_exten, self.auto_add_key_template)
        else:
            self.auto_add_key_template = self.man_add_key(self.auto_add_key_template)
        return self.auto_add_key_template

    # BILHETAGEM VOIP
    def billing_voip(self, billing, template, ticket_voztotal):

        self.bi_billing_voip = billing
        self.bi_template_voip = template
        self.bi_ticket_voztotal = ticket_voztotal

        for self.bi_string_voip in self.bi_template_voip:
            self.bi_occurrence_voip += 1

        while True:
            if self.bi_billing_voip is None:
                os.system('cls')
                self.bi_billing_voip = input(tools.centralize_message(main.banner + '\n\n\nEscolha a bilhetagem:'
                                                                                    '\n\n1-Ramal\n2-Chave') + '\n\n Bilhetagem > ')
                if self.bi_billing_voip == '1':
                    self.facilities.os_voip_extension_tag += str(self.bi_new_extension) + ': '
                    if self.bi_ticket_voztotal is None:
                        self.bi_billing_extension = None
                    else:
                        self.bi_billing_extension = tools.search_in_ticket(self.facilities.os_voip_billing_tag2, self.bi_ticket_voztotal, self.facilities.os_voip_extension_pattern)
                    if self.bi_billing_extension is not None:
                        self.bi_template_voip = self.auto_add_range(self.bi_template_voip, self.bi_ticket_voztotal)
                        return self.bi_template_voip
                    else:
                        self.bi_template_voip = self.man_add_range(self.bi_template_voip)
                        return self.bi_template_voip
                elif self.bi_billing_voip == '2':
                    self.bi_template_voip = self.auto_add_key(self.bi_template_voip, self.bi_ticket_voztotal)
                    return self.bi_template_voip
                else:
                    print(tools.centralize_message('\nEntrada Invalida'))
            else:
                if self.bi_billing_voip == 'Rml':
                    self.facilities.os_voip_extension_tag += str(self.bi_new_extension) + ': '
                    if self.bi_ticket_voztotal is None:
                        self.bi_billing_extension = None
                    else:
                        self.bi_billing_extension = tools.search_in_ticket(self.facilities.os_voip_extension_tag, self.bi_ticket_voztotal, self.facilities.os_voip_extension_pattern)
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

    # INTERNET LINK + VOZ TOTAL R2
    def audio_internet_voz_r2(self):
        try:
            # self.ivr2_archive = open(main.path + 'Audiocodes\\Audiocodes_Internet_Voz_R2.txt')
            # Busca o padrão de configuração no servidor

            self.audio_ivr2_archive = open('C:\\Users\\Public\\Documents\\Audiocodes_Internet_Voz_R2.txt')
            # Busca o template padrão de configuração local

            self.audio_ivr2_template = list(self.audio_ivr2_archive.readlines())
        except TypeError:
            print(tools.centralize_message('\nTemplate Não Localizado'))
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
            self.audio_ivr2_hostname = tools.search_in_ticket(self.facilities.os_host_tag, self.audio_ivr2_ponto_de_acesso,
                                                        self.facilities.os_host_pattern)

            # CIRCUITO DE INTERNET
            self.audio_ivr2_inter_circuit = tools.search_in_ticket(self.facilities.os_inter_circ_tag, self.audio_ivr2_internet_link,
                                                            self.facilities.os_inter_circ_pattern)

            # VLAN DE INTERNET
            self.audio_ivr2_inter_vlan = tools.search_in_ticket(self.facilities.os_inter_vlan_tag, self.audio_ivr2_internet_link,
                                                         self.facilities.os_inter_vlan_pattern)

            # WAN DE INTERNET
            self.audio_ivr2_inter_wan = tools.search_in_ticket(self.facilities.os_inter_wan_tag, self.audio_ivr2_internet_link,
                                                         self.facilities.os_inter_wan_pattern)
            # LAN DE INTERNET
            self.audio_ivr2_inter_lan = tools.search_in_ticket(self.facilities.os_inter_lan_tag, self.audio_ivr2_internet_link,
                                                         self.facilities.os_inter_lan_pattern)
            # VELOCIDADE DE INTERNET
            self.audio_ivr2_inter_speed = tools.search_in_ticket(self.facilities.os_inter_speed_tag, self.audio_ivr2_internet_link,
                                                           self.facilities.os_inter_speed_pattern)

            # CIRCUITO DE VOIP
            self.audio_ivr2_voip_circuit = tools.search_in_ticket(self.facilities.os_voip_circ_tag, self.audio_ivr2_voz_total,
                                                            self.facilities.os_voip_circ_pattern)

            # VLAN DE VOIP
            self.audio_ivr2_voip_vlan = tools.search_in_ticket(self.facilities.os_voip_vlan_tag, self.audio_ivr2_voz_total,
                                                         self.facilities.os_voip_vlan_pattern)

            # WAN DE VOIP
            self.audio_ivr2_voip_wan = tools.search_in_ticket(self.facilities.os_voip_wan_tag, self.audio_ivr2_voz_total,
                                                         self.facilities.os_voip_wan_pattern)

            # CANAIS DE VOIP
            self.audio_ivr2_voip_channel = tools.search_in_ticket(self.facilities.os_voip_channel_tag, self.audio_ivr2_voz_total,
                                                         self.facilities.os_voip_channel_pattern)

            # SBC DE VOIP
            self.audio_ivr2_voip_sbc = tools.search_in_ticket(self.facilities.os_voip_sbc_tag, self.audio_ivr2_voz_total,
                                                            self.facilities.os_voip_sbc_pattern)

            # BILHETAGEM DE VOIP
            self.audio_ivr2_voip_billing = tools.search_in_ticket(self.facilities.os_voip_billing_tag, self.audio_ivr2_voz_total,
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

    # GERA SCRIPT
    def generate_script(self):
        if self.prod_equipment == 'Audiocodes':
            if self.prod_product == 'Internet Link + Voz Total R2':
                self.gener_template = self.audio_internet_voz_r2()
                return self.gener_template


class Support:

    def __init__(self, product, equipment):
        self.supp_product = product
        self.supp_equipment = equipment
        self.supp_audi_products = 'Internet Link', 'Voz Total R2', 'Voz Total ISDN', 'Voz Total PABX IP', \
                                  'Internet Link + Voz Total R2', 'VPN IP', 'VPN IP + Voz Total R2', \
                                  'VPN IP + Voz Total ISDN', 'VPN IP + Voz Total PABX IP'
        self.supp_veri_check = False

    def audiocodes(self):
        if self.supp_product in self.supp_audi_products:
            return True

    def verify(self):
        if self.supp_equipment == 'Audiocodes':
            self.supp_veri_check = self.audiocodes()
            if self.supp_veri_check:
                return True
        else:
            return False


class RunAudiocodes:

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

        """Esse método faz a leitura da quantidade de bytes que estão pendentes na serial e retorna para uma string
        onde são armazenados como da interação do roteador como software"""

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

        """Esse método envia uma string codificada em bytes para a serial e retorna o log que foi gerado pelo método
                'read_serial'"""

        self.audio_send_comm_console = console
        self.audio_send_comm_cmd = cmd

        self.audio_send_comm_console.write(self.audio_send_comm_cmd.encode() + str.encode('\n'))
        time.sleep(1)
        return self.audio_read_serial(self.audio_send_comm_console)

    def audio_check_logged_in(self, console):

        """Esse método envia quebras de linhas como comando para serial e faz a leitura do log que retorna verdadeiro
        caso o roteador esteja em modo de configuração 'enable'"""

        self.audio_check_log_console = console

        self.audio_check_log_prompt = str(self.audio_send_command(self.audio_check_log_console, cmd='\n'))
        time.sleep(1)
        if '#' in self.audio_check_log_prompt:
            return True
        else:
            return False
        pass

    def audio_logout(self, console):

        """Esse método utiliza 'check_logged_in' para verificar o status de acesso do roteador e enviar o comando 'exit'
        enquanto o roteador não estiver solicitando Usuário e Senha"""

        self.audio_logout_console = console

        # print(tools.centralize_message('\nRealizando Logout! Aguarde...'))
        while self.audio_check_logged_in(self.audio_logout_console):
            self.audio_send_command(self.audio_logout_console, cmd='exit')
            time.sleep(.5)
        pass
        # print(tools.centralize_message('\nRealizado Logout com Sucesso!\n'))

    def audio_login(self, console):

        """Esse método utiliza 'check_logged_in' para verificar o status do roteador e envia o usuário e
        senha realizando acesso ao modo de configuração"""

        self.audio_login_console = console

        self.audio_login_status = self.audio_check_logged_in(self.audio_login_console)
        if self.audio_login_status:
            # print(tools.centralize_message('\nJá Logado!'))
            return None

        # print(tools.centralize_message('\nRealizando Login! Aguarde...'))
        while True:
            self.audio_login_prompt = str(self.audio_send_command(console, cmd='\n'))
            if 'Username' in self.audio_login_prompt:
                self.audio_login_prompt = str(self.audio_send_command(self.audio_login_console, self.audio_login_username))
                time.sleep(1)
                self.audio_login_prompt = str(self.audio_send_command(self.audio_login_console, self.audio_login_password))
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
                self.audio_login_prompt = str(self.audio_send_command(self.audio_login_console, self.audio_login_password))
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
        while True:
            os.system('cls')
            self.audio_conect_config_com = input(tools.centralize_message(main.banner + '\n\n\nDIGITE PORTA COM: \tEx. 3:') + '\n\n\n COM > ')
            if self.audio_conect_config_com.isnumeric():
                try:
                    self.audio_conect_console = serial.Serial(port='COM' + self.audio_conect_config_com, baudrate=115200, parity="N", stopbits=1, bytesize=8, timeout=8)
                except BaseException:
                    print(tools.centralize_message('\nPorta COM Indisponível'))
                    time.sleep(2)
                    continue
                if self.audio_conect_console.isOpen():
                    print(tools.centralize_message('Porta COM' + self.audio_conect_config_com + ' Conectada!\n'))
                    time.sleep(2)
                    self.audio_send_command(self.audio_conect_console, cmd='\n')
                    return self.audio_conect_console
                else:
                    print(tools.centralize_message('\nPorta COM Indisponivel: ' + self.audio_conect_config_com))
                    time.sleep(2)
                    continue

    def audio_check_router(self, console):

        """Envia quebra de linha e faz a leitura da quantidade de bytes que foram retornados da serial,  no caso da
               serial retornar 0 o equipamento pode estar ausente
               mais de 16 bytes ele está iniciando ou com bug de firmware """

        self.audio_check_rou_console = console
        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nVerificando Equipamento! Aguarde...'))

        while True:
            self.audio_check_rou_console.write(self.audio_check_rou_cmd.encode())
            time.sleep(5)
            self.audio_check_rou_data_bytes = self.audio_check_rou_console.inWaiting()
            if self.audio_check_rou_data_bytes == 26:
                self.audio_check_rou_prompt = str(self.audio_send_command(self.audio_check_rou_console, cmd='\n'))
                if 'Mediant 500 - MSBR>' in self.audio_check_rou_prompt or 'Mediant 500 - MSBR#' in self.audio_check_rou_prompt:
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
                    print(tools.centralize_message(main.banner + '\nEquipamento sem acesso, verifique!'))
                    time.sleep(2)
                    self.audio_read_serial(self.audio_conect_console)
                    return False
            else:
                self.audio_check_rou_prompt = str(self.audio_send_command(self.audio_conect_console, cmd='\n'))
                if 'Username' in self.audio_check_rou_prompt or 'Mediant 500 - MSBR>' in self.audio_check_rou_prompt or 'Mediant 500 - MSBR#' in self.audio_check_rou_prompt:
                    return True
                else:
                    continue

    def audio_check_version(self, console):

        """Esse método realiza a verificação da versão de firmware do roteador"""

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

        self.audio_check_server_console = console

        self.audio_check_server_lines = int((len(self.audio_check_server_commands)))
        for self.audio_check_server_string in range(0, self.audio_check_server_lines):
            self.audio_send_command(self.audio_check_server_console, cmd=self.audio_check_server_commands[self.audio_check_server_string])
        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\nVerificando Servidor TFTP! Aguarde...'))
        self.audio_send_command(self.audio_check_server_console, cmd='ping ' + main.path_server + '\n')
        time.sleep(5)
        self.audio_check_server_prompt = str(self.audio_read_serial(self.audio_check_server_console))
        if '4 packets transmitted, 0 packets received' in self.audio_check_server_prompt or 'hostname resolution failed' in self.audio_check_server_prompt:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\nServidor TFTP Indisponível, Verifique Ponto de Rede'))
            time.sleep(2)
            return False
        elif 'Reply from ' + main.path_server in self.audio_check_server_prompt:
            print(tools.centralize_message('\n\nServidor TFTP OK!'))
            time.sleep(2)
            return True

    def audio_update_brtons(self, console):

        self.audio_update_brtons_console = console

        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nAtualizando... br_tons_Mediant_5.6_to_6.8.dat'))
        # self.audio_send_command(console, cmd='copy call-progress-tones from TFTP://' + main.path_server + '/br_tons_Mediant_5.6_to_6.8.dat')
        self.audio_send_command(console, cmd='copy call-progress-tones from TFTP://' + main.local_host +'/br_tons_Mediant_5.6_to_6.8.dat')
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
                    self.audio_update_brtons_prompt = (self.audio_send_command(self.audio_update_brtons_console, cmd='\n'))
                    time.sleep(2)
                    continue

    def audio_update_castable(self, console):

        self.audio_update_castable_console = console

        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nAtualizando... R2_BR_ANI_2s_DPLN_DA_RX_No_Sus_v3.dat'))
        # self.audio_send_command(self.audio_update_castable_console, cmd='copy cas-table from TFTP://' + main.path_server + '/R2_BR_ANI_2s_DPLN_DA_RX_No_Sus_v3.dat')
        self.audio_send_command(self.audio_update_castable_console, cmd='copy cas-table from TFTP://' + main.local_host +'/R2_BR_ANI_2s_DPLN_DA_RX_No_Sus_v3.dat')
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
                    self.audio_update_castable_prompt = str(self.audio_send_command(self.audio_update_castable_console, cmd='\n'))
                    time.sleep(2)

    def audio_log_copy(self):

        self.audio_log_copy_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_log_copy_string = '\nAtualizando:  ' + self.audio_update_cmp_firmware
        for self.audio_log_copy_up in range(0, 7):
            self.audio_log_copy_dot = '.'
            if self.audio_log_copy_up == 7:
                self.audio_log_copy_dot = ''
            self.audio_log_copy_dot *= self.audio_log_copy_up
            for self.audio_log_copy_update in self.audio_log_copy_lista:
                os.system('cls')
                print(tools.centralize_message(main.banner + self.audio_log_copy_string + '\n\nCopiando firmware' + self.audio_log_copy_dot + self.audio_log_copy_update))
                time.sleep(.2)

    def audio_log_save(self):

        self.audio_log_save_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_log_save_string = '\nAtualizando:  ' + self.audio_update_cmp_firmware
        for self.audio_log_save_up in range(0, 7):
            self.audio_log_save_dot = '.'
            if self.audio_log_save_up == 7:
                self.audio_log_save_dot = ''
            self.audio_log_save_dot *= self.audio_log_save_up
            for self.audio_log_save_update in self.audio_log_save_lista:
                os.system('cls')
                print(tools.centralize_message(main.banner + self.audio_log_save_string + '\n\nSalvando firmware' + self.audio_log_save_dot + self.audio_log_save_update))
                time.sleep(.2)

    def audio_log_restart(self):

        self.audio_log_restart_lista = ['|', '/', '—', '\\', '|', '']
        self.audio_log_restart_string = '\nAtualizando:  ' + self.audio_update_cmp_firmware
        for self.audio_log_restart_up in range(0, 7):
            self.audio_log_restart_dot = '.'
            if self.audio_log_restart_up == 7:
                self.audio_log_restart_dot = ''
            self.audio_log_restart_dot *= self.audio_log_restart_up
            for self.audio_log_restart_update in self.audio_log_restart_lista:
                os.system('cls')
                print(tools.centralize_message(main.banner + self.audio_log_restart_string + '\n\nReiniciando' + self.audio_log_restart_dot + self.audio_log_restart_update))
                time.sleep(.2)

    def audio_update_cmp(self, console):

        self.audio_update_cmp_console = console

        os.system('cls')
        print(tools.centralize_message(main.banner + '\nVerificando...  ' + self.audio_update_cmp_firmware + '\n'))
        # self.audio_send_command(self.audio_update_cmp_console, cmd='copy firmware from TFTP://' + main.path_server + '/' + self.audio_update_cmp_firmware)
        self.audio_send_command(self.audio_update_cmp_console, cmd='copy firmware from TFTP://' + main.local_host +'/' + self.audio_update_cmp_firmware)
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
                            # print('\nChecou a versão')
                            continue
                        pass
                    else:
                        # print('\nChecou o Login')
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
                                            print(tools.centralize_message(main.banner + self.audio_log_restart_string + '\n\nReiniciando'))
                                            continue
                                elif 'Username' in prompt:
                                    break
                                else:
                                    self.audio_log_save()
                                    os.system('cls')
                                    print(tools.centralize_message(main.banner + self.audio_log_save_string + '\n\nSalvando firmware'))
                                    continue
                        elif 'Username' in prompt:
                            break
                        else:
                            self.audio_log_copy()
                            os.system('cls')
                            print(tools.centralize_message(main.banner + self.audio_log_copy_string + '\n\nCopiando firmware'))
                            continue

    def audio_update_full(self, console):

        """Esse método é realiza as atualizações do roteador Audiocodes"""

        self.audio_update_console = console

        # self.audio_update_check = self.audio_check_server(self.audio_update_console)
        self.audio_update_check = True

        if self.audio_update_check:
            self.audio_update_brtons(self.audio_update_console)
            self.audio_update_castable(self.audio_update_console)
            self.audio_update_cmp(self.audio_update_console)

    def audio_configure(self, console, template):

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
                print(tools.centralize_message(main.banner + '\n\nConfigurando' + self.audio_configure_dot + self.audio_configure_front))
                time.sleep(.05)
            self.audio_configure_log = str(self.audio_send_command(self.audio_configure_console, cmd=self.audio_configure_template[self.audio_configure_cmd]))
            if 'Invalid command' in self.audio_configure_log:
                with open('AutoScript\\logs\\Audiocodes.txt', 'w') as self.audio_configure_archive:
                    self.audio_configure_archive.writelines(self.audio_configure_log)
                break
            else:
                self.audio_configure_up += 1
            pass
        pass

    def audio_serial(self, template):

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

        """Recebe uma String com o número da ordem de serviço a ser pesquisada no servidor"""

        self.sear_order_id = order_id
        try:
            #self.sear_dir = os.listdir(main.path_server + 'Bilhete_OSM')
            # Faz a leitura do nome dos arquivos no diretório do servidor

            self.sear_dir = os.listdir('C:\\Users\\Public\\Documents\\')
            # Faz a leitura do nome dos arquivos no diretório local

            for self.sear_file in self.sear_dir:
                if self.sear_order_id in self.sear_file:  # Compara o número da ordem de serviço com o nome dos arquivos

                    #self.sear_archive = open(self.path_server + 'Bilhete_OSM\\' + self.sear_file, 'r')
                    # Busca o arquivo no servidor

                    self.sear_archive = open('C:\\Users\\Public\\Documents\\' + self.sear_file, 'r')
                    # Busca o arquivo em pasta local

                    self.sear_data = list(self.sear_archive.readlines())
                    # Caso encontrado o conteúdo do arquivo é copiado

                    self.sear_temp = {self.sear_order_id: self.sear_data}
                    # Armazena o número da ordem de serviço junto com o conteúdo do arquivo em um dicionário

                    return self.sear_temp  # Retorna o dicionário
            print(
                tools.centralize_message('\nBilhete_Ordem_' + self.sear_order_id + '_Acesso_LP(?).txt, Não Localizado!'))
            time.sleep(2)
            return None  # Arquivo não encontrado é retornado 'None'
        except FileNotFoundError:
            print(tools.centralize_message('\nServidor não Localizado!'))
            time.sleep(2)
            return None  # Servidor indisponível é retornado 'None'
        except OSError:
            print(tools.centralize_message('\nDiretório não Localizado!'))
            time.sleep(2)
            return None  # Diretório indisponível é retornado 'None'

    def discover_signaling(self, ticket):

        """Recebe um Dicionário com o número da OS e o conteúdo do arquivo de Voz Total"""

        self.dis_sign_ticket = ticket
        while True:
            if self.dis_sign_signaling is None:
                # Caso não seja encontrado no arquivo é enviado uma solicitação ao usuário
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
                    # Pesquisa no conteúdo do arquivo para identificar o tipo de sinalização do produto
                    self.dis_sign_signaling = tools.search_in_ticket(self.dis_sign_tag, self.dis_sign_values,
                                                                     self.dis_sign_pattern)

                if self.dis_sign_signaling == 'R2':  # Caso seja encontrado é comparado com o padrão disponível
                    return 'Voz Total R2'
                else:
                    # Caso não seja compativel com o padrão disponível  ou não seja encontrado é solicitado ao usuário
                    continue

    def discover_the_product(self, tickets):

        """Recebe um Dicionário com os números das OSs e os conteúdos dos arquivos"""

        self.dis_prod_tickets = tickets
        for self.dis_prod_values in self.dis_prod_tickets.values():
            # Pesquisa no conteúdo do arquivo para identificar o tipo do produto
            self.dis_prod_product = tools.search_in_ticket(self.dis_prod_tag,
                                                           self.dis_prod_values, self.dis_prod_pattern)

            self.dis_prod_product = self.dis_prod_product[10:]  # Faz um filtro na sring deixando somente o nome produto

        self.dis_prod_product = OS.validate_product(self, self.dis_prod_product)

        for self.dis_prod_keys in self.dis_prod_tickets_products.keys():
            # Faz uma pesquisa nas chaves do dicionário
            if self.dis_prod_keys == self.dis_prod_product:
                # Caso o produto seja repetido é atribuido um erro para informar ao usuário e solicitar uma nova entrada
                print(tools.centralize_message(self.dis_prod_keys + ' + ' + self.dis_prod_product))
                raise AttributeError

        self.dis_prod_tickets_products.update({self.dis_prod_product: self.dis_prod_values})
        # Caso seja um produto nova é adicionado a um dicionário e retornado junto com o nome do produto atual
        return self.dis_prod_tickets_products, self.dis_prod_product

    def discover_final_product(self, tickets):

        """Recebe um Dicionário com os números das OSs e os conteúdos dos arquivos"""

        self.dis_fin_tickets = tickets
        while True:
            if self.dis_fin_tickets is None:
                # Caso não seja encontrado no arquivo é enviado uma solicitação ao usuário
                os.system('cls')
                self.dis_fin_product = input(tools.centralize_message(self.banner +
                                                                     '\n\n\nESCOLHA O PRODUTO:'
                                                                     '\n\n1 - Internet Link + Voz Total R2'
                                                                     '\n2 - Internet Link'
                                                                     '\n3 - Voz Total') + '\n\n\n Produto >\t')
                if self.dis_fin_product == '1':
                    return 'Internet Link + Voz Total R2'
                elif self.dis_fin_product == '2':
                    return 'Internet Link'
                elif self.dis_fin_product == '3':
                    return 'Voz Total'
                else:
                    continue
            else:
                for self.dis_fin_string in self.dis_fin_tickets.keys():
                    # Pesquisa nas chaves do dicionário o produto é igual a Voz Total
                    if self.dis_fin_string == 'Voz Total':
                        self.dis_fin_voztotal = {self.dis_fin_string: self.dis_fin_tickets[self.dis_fin_string]}
                        # Caso o produto seja Voz Total o conteúdo do bilhete é pesquisado

                        self.dis_fin_signaling = self.discover_signaling(self.dis_fin_voztotal)
                        # ÉChamado a função 'discover_signaling()' para identificar a sinalização de voz

                        self.dis_fin_final_product.append(self.dis_fin_signaling)
                        # É criado uma lista com o nome dos produtos a serem configurados já com a sinalização de voz
                    else:
                        self.dis_fin_final_product.append(self.dis_fin_string)
                        # É criado uma lista com o nome dos produtos a serem configurados

                if 'Internet Link' in self.dis_fin_final_product and 'Voz Total R2' in self.dis_fin_final_product and \
                        'Ponto de Acesso' in self.dis_fin_final_product:
                    return 'Internet Link + Voz Total R2'
                elif 'Internet Link' in self.dis_fin_final_product:
                    return 'Internet Link'
                elif 'Voz Total R2' in self.dis_fin_final_product:
                    return 'Voz Total R2'
                else:
                    self.dis_fin_tickets = None
                    # Caso o produto não esteja disponível é solicitado a informação ao usuário
                    continue

    def discover_router(self, tickets):

        """Recebe um Dicionário com os números das OSs e os conteúdos dos arquivos"""

        self.dis_rout_tickets = tickets

        while True:
            if self.dis_rout_tickets is None:
                # Caso não seja encontrado no arquivo é enviado uma solicitação ao usuário
                os.system('cls')
                self.dis_rout_router = input(tools.centralize_message(self.banner + '\n\n\n'
                                                                                   'ESCOLHA O MODELO DO EQUIPAMENTO:'
                                                                                   '\n\n1 - Audiocodes') + '\n\n\n '
                                                                                                           'Roteador> ')
                if self.dis_rout_router == '1':
                    return 'Audiocodes'
                else:
                    print(tools.centralize_message('\nOpção Invalida!'))
                    time.sleep(2)
                    continue
            else:
                for self.dis_rout_values in self.dis_rout_tickets.values():
                    # Pesquisa nos valores do dicionário o modelo de roteador
                    self.dis_rout_router = tools.search_in_ticket(self.dis_rout_tag, self.dis_rout_values,
                                                                  self.dis_rout_pattern)
                    if self.dis_rout_router is None:
                        pass
                    elif 'Audiocodes' in self.dis_rout_router:

                        self.dis_rout_router = self.dis_rout_router[11:]
                        # Faz um filtro na sring deixando somente o nome do roteador

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
            # Solicita a entrada ao usuário

            if self.menu_order_id == '?' or self.menu_order_id == 'h' or self.menu_order_id == 'H':
                # Indica as opções caso seja solicitada ajuda '?'
                input('\n ?,H,Help\t\tAjuda\n Enter\t\t\tInicia Execução\n I\t\t\tRetorna ao Início'
                      '\n M\t\t\tInformar Dados Manualmente\n S\t\t\tEncerra o Sistema\n')
                continue

            elif self.menu_order_id == '':
                # Interrompe as entradas após ter recebido ao menos uma ordem de serviço
                if not self.menu_tickets_order_id:
                    print(tools.centralize_message('\nMínimo uma OS para Execução!'))
                    time.sleep(2)
                    continue
                else:
                    self.menu_run = 0

            elif self.menu_order_id == 'i' or self.menu_order_id == 'I':
                # Retorna ao inicio
                return 'i'

            elif self.menu_order_id == 'm' or self.menu_order_id == 'M':
                # Continua a execução solicitando todos os dados ao usuário
                self.menu_tickets_product = None
                self.menu_order_id = False
                break

            elif self.menu_order_id == 's' or self.menu_order_id == 'S':
                # Encerra o sistema
                sys.exit()

            else:
                self.menu_check_id = OS.validate_id(self, self.menu_order_id)
                if self.menu_check_id:
                    try:
                        self.menu_temp = self.search_the_file(self.menu_order_id)
                        # Chama a função 'search_the_file()' e passa o número da OS como parâmetro
                        # Caso o retorno seja 'None' gera um 'TypeError'

                        self.menu_tickets_order_id.update(self.menu_temp)
                        # Armazena o retorno da 'search_the_file()' e um dicionário com números de OS

                        self.menu_temp, self.menu_product = self.discover_the_product(self.menu_temp)
                        # descobri o nome do produto
                        # Caso o produto seja repetido gera um 'AttributeError'
                        # Caso o retorno seja 'None' gera um 'TypeError'

                        self.menu_tickets_product.update(self.menu_temp)
                        # Armazena o retorno da 'discover_the_product()' e um outro dicionário com nomes de produtos

                        self.menu_new_banner += self.menu_order_id + ': ' + self.menu_product + '   '.center(10, ' ')
                        # cria um string com o nome do produto e o númeor da OS centralizando com 10 pixels de espaço
                        # Caso o retorno de 'discover_the_product()' seja 'None' gera um 'TypeError'

                        self.menu_run -= 1
                        # decrementa 1 da execução de entradas

                    except TypeError:
                        continue
                    except AttributeError:
                        print(tools.centralize_message('\nCombinação de produtos Invalida!'))
                        time.sleep(2)
                        continue
        if self.menu_order_id:
            os.system('cls')
            print(self.banner + '\n\n\n' + self.menu_new_banner)
            time.sleep(2)
        # Mostra o banner com os produtos seguidos das OSs

        self.menu_equipment = self.discover_router(self.menu_tickets_product)
        # Chama o método 'discover_router()' para identificar o modelo de roteador

        self.menu_fin_product = self.discover_final_product(self.menu_tickets_product)
        # Chama o método 'discover_final_product()' para identificar o produto final a ser configurado

        self.menu_support = Support(self.menu_fin_product, self.menu_equipment)

        if self.menu_support:
            return self.menu_tickets_product, self.menu_fin_product, self.menu_equipment
            # Retorna um dicionário com o nome dos produtos como chave e o conteúdo de cada arquivo como valor


if __name__ == "__main__":

    while True:
        tools = Tools()
        main = Main()
        config = RunAudiocodes()

        tickets, product, equipment = main.menu()

        if tickets == 'i':  # Caso o retorno de 'menu()' seja 'i' é reinicializado o sistema
            continue

        if tickets:
            generate_script = Product(equipment, product, tickets)
            template = generate_script.generate_script()
        else:
            generate_script = Product(equipment, product, None)
            template = generate_script.generate_script()

        with open('Audiocodes.txt', 'w') as archive:
            archive.writelines(template)

        os.system('cls')
        print(tools.centralize_message(main.banner + '\n\n\nScript Gerado com Sucesso!'))
        time.sleep(3)

        check = config.audio_serial(template)

        if check:
            os.system('cls')
            print(tools.centralize_message(main.banner + '\n\n\nRouter Configurado com Sucesso!'))
            time.sleep(3)
