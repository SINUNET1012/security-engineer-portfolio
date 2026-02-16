구버전 (Apache1 : apache 2.4)	apache
신버전 (Apache2 : apache 2.6)	httpd

설치 조건 : Apache, MariaDBPHP


================================================================
사전 작업 확인

0. 사용자 root로 전환
sudo su -

#일반 사용자에게 sudo 권한 부여
usermod -aG sudo [사용자]
usermod -aG sudo lemon



1. selinux 확인 
[root@localhost ~]# getenforce
Disabled
[root@localhost ~]#

[root@localhost ~]# setenforce 1   ← 설정파일을 수정하지 않고 상태값을 바꾼다. 
                                                            (리부팅 후 초기화)
setenforce: SELinux is disabled
[root@localhost ~]#

0 : OFF
1 : ON

2. 방화벽 → systemctl status firewalld
[root@localhost ~]# systemctl status firewalld
○ firewalld.service - firewalld - dynamic firewall daemon
     Loaded: loaded (/usr/lib/systemd/system/firewalld.service; disabled; preset: enabled)
     Active: inactive (dead)
       Docs: man:firewalld(1)
[root@localhost ~]#

#현재 방화벽 비활성화 상태

3. 리포지터리 확인
	epel-release / remi-release   설치
            crb  : dnf config-manager --set-enabled crb (설정)
                     dnf install epel-next-release -y (확장팩 개념)

Installed:
  epel-next-release-9-10.el9.noarch

Complete!
[root@localhost ~]#

에러방지 : dnf -y install inxi

#사전 설정 완료

★ 설치 후 확인

MariaDB
-------------------------------------------------
접속
mysql -u root -p

현재 사용자 계정 확인
SELECT User, Host, plugin FROM mysql.user;

remoteuser 권한 확인
SHOW GRANTS FOR 'remoteuser'@'%';

접속 허용 여부
SELECT CURRENT_USER();

패스워드 변경 또는 재설정
ALTER USER 'remoteuser'@'%' IDENTIFIED BY '원하는비밀번호';
FLUSH PRIVILEGES;
-------------------------------------------------

PHP
-------------------------------------------------
테스트 페이지 접속
서버의 웹 문서 루트 확인: 보통 Ubuntu 기준 /var/www/html/
테스트용 PHP 파일 생성
sudo bash -c 'echo "<?php phpinfo(); ?>" > /var/www/html/info.php'
웹 브라우저에서 접속
http://<서버IP>/info.php
-------------------------------------------------

PHPMyAdmin
-------------------------------------------------
http://<서버IP>/phpmyadmin

사용자 : phpmyadmin

