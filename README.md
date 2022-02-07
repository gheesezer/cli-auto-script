# AutoScript

Esta aplicação CLI foi desenvolvida durante o inicio dos meus estudos e utilizada para facilitar o processo de atualização e configuração para equipamentos de telecom (roteadores,switches, modem's...) em meu trabalho na época, pode ser adaptada para qualquer tipo de conexão serial através de CLI.

Este software tem a funcionalidade de gerar um script de configuração a partir de um modelo definido e exportá-lo para um arquivo .txt,
após a validação da configuração, um número de porta serial é solicitado, onde será aplicado as configurações geradas. 

Antes de aplicar o script, é executado uma verificação de versão e se estiver desatualizado será apontado para um servidor TFTP para baixar uma versão mais nova.

As informações necessárias para gerar o script são pesquisadas na rede ou pasta local, mas se você não
tiver um caminho de diretório válido será solicitado a inserir as entradas manualmente para gerar o script.

Neste protótipo, foi usado um roteador Audiocodes Mediant 500 - MSBR

O equipamento de teste possui uma taxa de transmissão de 115200 na porta serial e é atualizado para a versão de firmware 'Versão do software: 6.80A.286.002'. Esses dados podem ser modificados de acordo com o equipamento que será atualizado e configurado.

O ambiente de desenvolvimento e testes foi Windows e os diretórios e comandos importados para o sistema precisam ser alterados para outro sistema operacional caso necessário.


![](https://i.imgur.com/1DNWFaE.png)


![](https://i.imgur.com/vwR9rNv.png)


![](https://i.imgur.com/4rmLB6F.png)


![](https://i.imgur.com/U21TkX3.png)


Bibliotecas utilizadas:

https://github.com/pyserial/pyserial


Softwares utilizados:

https://www.putty.org/

http://tftpd32.jounin.net/tftpd32_download.html
