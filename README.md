# AutoScript

Esta aplicação foi desenvolvida para facilitar o processo de atualização e configuração em equipamentos de telecom (roteadores,switches, modem's...) e pode ser adaptada para qualquer tipo de conexão serial através de CLI.

Este software tem a funcionalidade de gerar um script de configuração a partir de um modelo definido e exportá-lo para um arquivo .txt,
após a validação da configuração, um número de porta serial é solicitado, onde será aplicado as configurações geradas. 

Antes de aplicar o script, é executado uma verificação de versão e se estiver desatualizado será apontado para um servidor TFTP para baixar uma versão mais nova.

As informações necessárias para gerar o script são pesquisadas na rede ou pasta local, mas se você não
tiver um caminho de diretório válido será solicitado a inserir as entradas manualmente para gerar o script.

Neste protótipo, foi usado um roteador Audiocodes Mediant 500 - MSBR

O equipamento de teste possui uma taxa de transmissão de 115200 na porta serial e é atualizado para a versão de firmware 'Versão do software: 6.80A.286.002'. Esses dados podem ser modificados de acordo com o equipamento que será atualizado e configurado.

O ambiente de desenvolvimento e testes foi Windows e os diretórios e comandos importados para o sistema precisam ser alterados para outro sistema operacional caso necessário.


![](https://i.imgur.com/Gj1cctE.png)


![](https://i.imgur.com/uUlheov.png)


![](https://i.imgur.com/9opI53u.png)


![](https://i.imgur.com/WtFEt0s.png)


Bibliotecas utilizadas:
https://github.com/pyserial/pyserial

Softwares utilizados:
https://www.putty.org/
http://tftpd32.jounin.net/tftpd32_download.html
