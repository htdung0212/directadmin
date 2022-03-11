#!/bin/sh

###############################################################################
# setup.sh
# DirectAdmin  setup.sh  file  is  the  first  file  to  download  when doing a
# DirectAdmin Install.  If  you  are unable to run this script with
# ./setup.sh  then  you probably need to set it's permissions.  You can do this
# by typing the following:
#
# chmod 755 setup.sh
#
# after this has been done, you can type ./setup.sh to run the script.
#
###############################################################################

color_reset=$(tput -Txterm sgr0)
green=$(tput -Txterm setaf 2)
red=$(tput -Txterm setaf 1)

echogreen () {
	echo "[setup.sh] ${green}$*${color_reset}"
}

echored () {
	echo "[setup.sh] ${red}$*${color_reset}"
}


if [ "$(id -u)" != "0" ]; then
	echored "You must be root to execute the script. Exiting."
	exit 1
fi

if ! uname -m | grep -m1 -q 64; then
	echored "This is a 32-bit machine, we support only 64-bit installations. Exiting."
	exit 1
fi

#Global variables
DA_CHANNEL=${DA_CHANNEL:="current"}
DA_PATH=/usr/local/directadmin
DACONF=${DA_PATH}/conf/directadmin.conf
DA_TQ="${DA_PATH}/data/task.queue"
DA_SCRIPTS="${DA_PATH}/scripts"
DA_CRON="${DA_SCRIPTS}/directadmin_cron"

SETUP_TXT="${DA_SCRIPTS}/setup.txt"

DL_SERVER=files.directadmin.com
BACKUP_DL_SERVER=files-de.directadmin.com

SYSTEMD=false
SYSTEMDDIR=/etc/systemd/system
if [ -d ${SYSTEMDDIR} ]; then
	if [ -e /bin/systemctl ] || [ -e /usr/bin/systemctl ]; then
		SYSTEMD=true
	fi
fi

case "${1}" in
	--help|help|\?|-\?|h)
		echo ""
		echo "Usage: $0 <license_key>"
		echo ""
		echo "or"
		echo ""
		echo "Usage: DA_CHANNEL=\"beta\" $0 <license_key>"
		echo ""
		echo "You may use the following environment variables to pre-define the settings:"
		echo "  DA_CHANNEL : Download channel: alpha, beta, current, stable, [commit-hash]"
		echo "    DA_EMAIL : Default email address"
		echo " DA_HOSTNAME : Hostname to use for installation"
		echo "  DA_ETH_DEV : Network device"
		echo "      DA_NS1 : pre-defined ns1"
		echo "      DA_NS2 : pre-defined ns2"
		echo ""
		echo "Just set any of these environment variables to non-empty value (for example, DA_SKIP_CSF=true) to:"
		echo "            DA_SKIP_FASTEST : do not check for fastest server"
		echo "                DA_SKIP_CSF : skip installation of CFS firewall"
		echo "      DA_SKIP_MYSQL_INSTALL : skip installation of MySQL/MariaDB"
		echo "         DA_SKIP_SECURE_PHP : skip disabling insecure PHP functions automatically"
		echo "        DA_SKIP_CUSTOMBUILD : skip all the CustomBuild actions"
		echo " DA_INTERACTIVE_CUSTOMBUILD : run interactive CustomBuild installation if DA_SKIP_CUSTOMBUILD is unset"
		echo " DA_FOREGROUND_CUSTOMBUILD  : run CustomBuild installation in foreground DA_SKIP_CUSTOMBUILD is unset"
		echo ""
		echo "To customize any CustomBuild options, we suggest using environment variables: https://docs.directadmin.com/getting-started/installation/overview.html#running-the-installation-with-predefined-options"
		echo ""
		exit 0
		;;
esac

if [ -e /etc/debian_version ]; then
        apt-get --quiet --yes update
fi

if ! command -v dig > /dev/null || ! command -v curl > /dev/null || ! command -v tar > /dev/null || ! command -v perl > /dev/null; then
	echogreen "Installing dependencies..."
	if [ "${OS}" = "FreeBSD" ]; then
		# FIXME remove wget once getLicense.sh is fixed
		pkg install -y curl perl5 bind-tools wget
		if [ ! -e /usr/bin/perl ] && [ -e /usr/local/bin/perl ]; then
			ln -s /usr/local/bin/perl /usr/bin/perl
		fi
	elif [ -e /etc/debian_version ]; then
		# FIXME remove wget once getLicense.sh is fixed
		apt-get --quiet --quiet --yes install curl tar perl bind9-dnsutils wget || apt-get --quiet --quiet --yes install curl tar perl dnsutils wget
	else
		# FIXME remove wget once getLicense.sh is fixed
		yum --quiet --assumeyes install curl tar perl bind-utils wget
	fi
fi

if ! command -v curl > /dev/null; then
	echored "Please make sure 'curl' tool is available on your system and try again."
	exit 1
fi
if ! command -v tar > /dev/null; then
	echored "Please make sure 'tar' tool is available on your system and try again."
	exit 1
fi
if ! command -v perl > /dev/null; then
	echored "Please make sure 'perl' tool is available on your system and try again."
	exit 1
fi

#HOSTNAME CHECKS#
if [ -n "${DA_HOSTNAME}" ]; then
	HOST="${DA_HOSTNAME}"
elif [ -e "/root/.use_hostname" ]; then
	HOST="$(head -n 1 < /root/.use_hostname)"
fi
if [ -z "${HOST}" ]; then
	if [ -x /usr/bin/hostnamectl ]; then
		HOST="$(/usr/bin/hostnamectl --static | head -n1)"
		if [ -z "${HOST}" ]; then
			HOST="$(/usr/bin/hostnamectl --transient | head -n1)"
		fi
		if [ -z "${HOST}" ]; then
			HOST="$(hostname -f 2>/dev/null)"
		fi
		if ! echo "${HOST}" | grep  -m1 -q '\.'; then
			HOST="$(grep -m1 -o "${HOST}\.[^[:space:]]*" /etc/hosts)"
		fi
	else
		HOST="$(hostname -f)"
	fi
fi

if [ "${HOST}" = "localhost" ]; then
	echo "'localhost' is not valid for the hostname. Setting it to server.hostname.com, you can change it later in Admin Settings"
	HOST=server.hostname.com
fi
if ! echo ${HOST} | grep -o '\.' | grep -m1 '\.'; then
	echo "'${HOST}' is not valid for the hostname. Setting it to server.hostname.com, you can change it later in Admin Settings"
	HOST=server.hostname.com
fi

random_pass() {
	PASS_LEN=$(perl -le 'print int(rand(6))+9')
	START_LEN=$(perl -le 'print int(rand(8))+1')
	END_LEN=$((PASS_LEN - START_LEN))
	SPECIAL_CHAR=$(perl -le 'print map { (qw{@ ^ _ - /})[rand 6] } 1')
	NUMERIC_CHAR=$(perl -le 'print int(rand(10))')
	PASS_START=$(perl -le "print map+(A..Z,a..z,0..9)[rand 62],0..$START_LEN")
	PASS_END=$(perl -le "print map+(A..Z,a..z,0..9)[rand 62],0..$END_LEN")
	PASS=${PASS_START}${SPECIAL_CHAR}${NUMERIC_CHAR}${PASS_END}
	echo "$PASS"
}

ADMIN_USER="admin"
ADMIN_PASS=$(random_pass)

# Get the other info
EMAIL=${ADMIN_USER}@${HOST}
if [ -s /root/.email.txt ] && [ -z "${DA_EMAIL}" ]; then
	EMAIL=$(head -n 1 < /root/.email.txt)
elif [ -n "${DA_EMAIL}" ]; then
	EMAIL="${DA_EMAIL}"
fi

TEST=$(echo "$HOST" | cut -d. -f3)
if [ "$TEST" = "" ]; then
	NS1=ns1.$(echo "$HOST" | cut -d. -f1,2)
	NS2=ns2.$(echo "$HOST" | cut -d. -f1,2)
else
	NS1=ns1.$(echo "$HOST" | cut -d. -f2,3,4,5,6)
	NS2=ns2.$(echo "$HOST" | cut -d. -f2,3,4,5,6)
fi

if [ -s /root/.ns1.txt ] && [ -s /root/.ns2.txt ] && [ -z "${DA_NS1}" ] && [ -z "${DA_NS2}" ]; then
	NS1=$(head -n1 < /root/.ns1.txt)
	NS2=$(head -n1 < /root/.ns2.txt)
elif [ -n "${DA_NS1}" ] && [ -n "${DA_NS2}" ]; then
	NS1="${DA_NS1}"
	NS2="${DA_NS2}"
fi



echo "* Installing pre-install packages ....";
if [ -e "/etc/debian_version" ]; then
	if [ "${OS_MAJ_VER}" -ge 10 ]; then
		apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libperl4-corelibs-perl libaio1 libaio-dev \
			zlib1g zlib1g-dev libcap-dev cron bzip2 zip automake autoconf libtool cmake pkg-config python3 libdb-dev libsasl2-dev \
			libncurses5 libncurses5-dev libsystemd-dev dnsutils quota patch logrotate rsyslog libc6-dev libexpat1-dev \
			libcrypt-openssl-rsa-perl libnuma-dev libnuma1 ipset libcurl4-openssl-dev curl psmisc libkrb5-dev ca-certificates
	else
		apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libperl4-corelibs-perl libaio1 libaio-dev zlib1g zlib1g-dev libcap-dev cron bzip2 zip automake autoconf libtool cmake pkg-config python libdb-dev libsasl2-dev libncurses5-dev libsystemd-dev dnsutils quota patch libjemalloc-dev logrotate rsyslog libc6-dev libexpat1-dev libcrypt-openssl-rsa-perl libnuma-dev libnuma1 ipset libcurl4-openssl-dev curl psmisc libkrb5-dev ca-certificates
	fi
else
	if [ "${OS_MAJ_VER}" -ge 8 ]; then
		yum -y install iptables wget tar gcc gcc-c++ flex bison make openssl openssl-devel perl quota libaio \
			libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
			autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel \
			psmisc net-tools systemd-devel libdb-devel perl-DBI xfsprogs rsyslog logrotate crontabs file \
			kernel-headers hostname ipset krb5-devel e2fsprogs
	elif [ "${OS_MAJ_VER}" -ge 7 ]; then
		yum -y install iptables wget tar gcc gcc-c++ flex bison make openssl openssl-devel perl quota libaio \
			libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
			autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel \
			psmisc net-tools systemd-devel libdb-devel perl-DBI perl-Perl4-CoreLibs xfsprogs rsyslog logrotate crontabs file kernel-headers ipset krb5-devel e2fsprogs
	else
		yum -y install wget tar gcc gcc-c++ flex bison make openssl openssl-devel perl quota libaio \
			libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
			autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel db4-devel ipset krb5-devel e2fsprogs
	fi
fi
echo "*";
echo "*****************************************************";
echo "";

###############################################################################
###############################################################################

# We now have all information gathered, now we need to start making decisions

if [ -e "/etc/debian_version" ] && [ -e /bin/bash ] && [ -e /bin/dash ]; then
	if ls -la /bin/sh | grep -q dash; then
		ln -sf /bin/bash /bin/sh
	fi
fi

#######
# Ok, we're ready to go.
if [ -e /etc/selinux/config ]; then
	perl -pi -e 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
	perl -pi -e 's/SELINUX=permissive/SELINUX=disabled/' /etc/selinux/config
fi

if [ -e /selinux/enforce ]; then
	echo "0" > /selinux/enforce
fi

if [ -e /usr/sbin/setenforce ]; then
	/usr/sbin/setenforce 0 || true
fi

if [ -e "/etc/debian_version" ] && [ -e /etc/apparmor.d ]; then
	mkdir -p /etc/apparmor.d/disable
	for aa_file in /etc/apparmor.d/*; do
		if [ -f "$aa_file" ]; then
			ln -s "$aa_file" /etc/apparmor.d/disable/ 2>/dev/null || true
			if [ -x /sbin/apparmor_parser ]; then
				/sbin/apparmor_parser -R "$aa_file" 2>/dev/null || true
			fi
		fi
	done
fi

if [ -s /usr/sbin/ntpdate ]; then
	/usr/sbin/ntpdate -b -u pool.ntp.org
fi

if [ -n "${DA_SKIP_MYSQL_INSTALL}" ]; then
	export mysql_inst=no
fi

#ensure /etc/hosts has localhost
if ! grep 127.0.0.1 /etc/hosts | grep -q localhost; then
	printf "127.0.0.1\t\tlocalhost" >> /etc/hosts
fi

OLDHOST=$(hostname --fqdn)
if [ "${OLDHOST}" = "" ]; then
	echo "old hostname is blank. Setting a temporary placeholder"
	/bin/hostname $HOST
	sleep 5
fi

###############################################################################

# write the setup.txt

NM=$(ip -o -f inet addr show scope global | grep -o 'inet [^ ]*' | grep -m1 -o '/[0-9]*' 2>/dev/null)
EXTERNAL_IP=$(curl --silent --location http://myip.directadmin.com 2>/dev/null | head -n1)
{
	echo "hostname=$HOST"
	echo "email=$EMAIL"
	echo "adminname=$ADMIN_USER"
	echo "adminpass=$ADMIN_PASS"
	echo "ns1=$NS1"
	echo "ns2=$NS2"
	echo "netmask=$NM"
	echo "ip=$EXTERNAL_IP"
} > ${SETUP_TXT}

chmod 600 ${SETUP_TXT}

###############################################################################
###############################################################################

#Create the diradmin user
createDAbase() {
	mkdir -p ${DA_PATH}
	if ! id diradmin; then
		if [ -e /etc/debian_version ]; then
			/usr/sbin/adduser --system --group --firstuid 100 --home ${DA_PATH} --no-create-home --disabled-login --force-badname diradmin
		else
			/usr/sbin/useradd -d ${DA_PATH} -r -s /bin/false diradmin 2> /dev/null
		fi
	fi

	chmod -f 755 ${DA_PATH}
	chown -f diradmin:diradmin ${DA_PATH}

	mkdir -p /var/log/directadmin
	mkdir -p ${DA_PATH}/conf
	chown -f diradmin:diradmin ${DA_PATH}/*
	chown -f diradmin:diradmin /var/log/directadmin
	chmod -f 700 ${DA_PATH}/conf
	chmod -f 700 /var/log/directadmin
	if [ -e /etc/logrotate.d ]; then
		cp $DA_SCRIPTS/directadmin.rotate /etc/logrotate.d/directadmin
		chmod 644 /etc/logrotate.d/directadmin
	fi

	mkdir -p /var/log/httpd/domains
	chmod 710 /var/log/httpd/domains
	chmod 710 /var/log/httpd

	mkdir -p /home/tmp
	chmod -f 1777 /home/tmp
	/bin/chmod 711 /home
	
	ULTMP_HC=/usr/lib/tmpfiles.d/home.conf
	if [ -s ${ULTMP_HC} ]; then
		#Q /home 0755 - - -
		if grep -m1 -q '^Q /home 0755 ' ${ULTMP_HC}; then
			perl -pi -e 's#^Q /home 0755 #Q /home 0711 #' ${ULTMP_HC};
		fi
	fi

	mkdir -p /var/www/html
	chmod 755 /var/www/html

	#If we have any AllowUsers in sshd_config - add root there as well
	if grep -q '^AllowUsers ' /etc/ssh/sshd_config;	then
		echo "" >> /etc/ssh/sshd_config
		echo "AllowUsers root" >> /etc/ssh/sshd_config
		chmod 710 /etc/ssh
	fi
}

#After everything else copy the directadmin_cron to /etc/cron.d
copyCronFile() {
	mkdir -p /etc/cron.d
	cp -f ${DA_SCRIPTS}/directadmin_cron /etc/cron.d/;
	chmod 600 /etc/cron.d/directadmin_cron
	chown root /etc/cron.d/directadmin_cron
		
	#CentOS/RHEL bits
	if [ ! -s /etc/debian_version ]; then
		CRON_BOOT=/etc/init.d/crond
		if ${SYSTEMD}; then
			CRON_BOOT=/usr/lib/systemd/system/crond.service
		fi

		if [ ! -s ${CRON_BOOT} ]; then
			echo ""
			echo "****************************************************************************"
			echo "* Cannot find ${CRON_BOOT}.  Ensure you have cronie installed"
			echo "    yum install cronie"
			echo "****************************************************************************"
			echo ""
		else
			if ${SYSTEMD}; then
				systemctl daemon-reload
				systemctl enable crond.service
				systemctl restart crond.service
			else
				${CRON_BOOT} restart
				/sbin/chkconfig crond on
			fi
		fi
	fi
}

#Copies the startup scripts over to the /etc/rc.d/init.d/ folder 
#and chkconfig's them to enable them on bootup
copyStartupScripts() {
	if ${SYSTEMD}; then
		cp -f ${DA_SCRIPTS}/directadmin.service ${SYSTEMDDIR}/
		cp -f ${DA_SCRIPTS}/startips.service ${SYSTEMDDIR}/
		chmod 644 ${SYSTEMDDIR}/startips.service

		systemctl daemon-reload

		systemctl enable directadmin.service
		systemctl enable startips.service
	else
		cp -f ${DA_SCRIPTS}/directadmin /etc/init.d/directadmin
		cp -f ${DA_SCRIPTS}/startips /etc/init.d/startips
		# nothing for debian as non-systemd debian versions are EOL
		if [ ! -s /etc/debian_version ]; then
			/sbin/chkconfig directadmin reset
			/sbin/chkconfig startips reset
		fi
	fi
}

getLicense() {
	if [ -e /root/.skip_get_license ]; then
		echo "/root/.skip_get_license exists. Not downloading license"
		return
	fi

	${DA_SCRIPTS}/getLicense.sh "$1" || exit 1
}

doSetHostname() {
	HN=$(grep hostname= ${SETUP_TXT} | cut -d= -f2)
	${DA_SCRIPTS}/hostname.sh "${HN}"
}

${DA_SCRIPTS}/doChecks.sh || exit 0

doSetHostname
createDAbase
copyStartupScripts
${DA_SCRIPTS}/fstab.sh
${DA_SCRIPTS}/cron_deny.sh

getLicense "$LK"

cp -f ${DA_SCRIPTS}/redirect.php /var/www/html/redirect.php

if grep -m1 -q '^adminname=' ${SETUP_TXT}; then
	ADMINNAME=$(grep -m1 '^adminname=' ${SETUP_TXT} | cut -d= -f2)
	if getent passwd ${ADMINNAME} > /dev/null 2>&1; then
		userdel -r "${ADMINNAME}" 2>/dev/null
	fi
	rm -rf "${DA_PATH}/data/users/${ADMINNAME}"
fi

#set ethernet device
if [ -n "${DA_ETH_DEV}" ] ; then
	ETH_DEV="${DA_ETH_DEV}"
elif [ -s ${DACONF} ]; then
	ETH_DEV=$(grep -E '^ethernet_dev=' ${DACONF} | cut -d= -f2)
fi

#moved here march 7, 2011
copyCronFile

${DA_PATH}/directadmin install  \
	"--adminname=${ADMIN_USER}" \
	"--adminpass=${ADMIN_PASS}" \
	"--email=${EMAIL}"          \
	"--hostname=${HOST}"        \
	"--network-dev=${ETH_DEV}"  \
	"--ip=${EXTERNAL_IP}"       \
	"--netmask=${NM}"           \
	"--ns1=${NS1}"              \
	"--ns2=${NS2}"              \
	|| exit 1

${DA_PATH}/directadmin p || true

echo ""
echo "System Security Tips:"
echo "  https://docs.directadmin.com/operation-system-level/securing/general.html#basic-system-security"
echo ""

if [ ! -s $DACONF ]; then
	echo "";
	echo "*********************************";
	echo "*";
	echo "* Cannot find $DACONF";
	echo "* Please see this guide:";
	echo "* https://docs.directadmin.com/directadmin/general-usage/troubleshooting-da-service.html#directadmin-not-starting-cannot-execute-binary-file";
	echo "*";
	echo "*********************************";
	exit 1;
fi

if ${SYSTEMD}; then
	if ! systemctl restart directadmin.service; then
		echored "Failed to start directadmin service, please make sure you have a valid license"
		systemctl --no-pager status directadmin.service
		exit 1
	fi
elif [ -e /etc/rc.d/init.d/directadmin ]; then
	/etc/rc.d/init.d/directadmin restart
fi

if [ -e /usr/local/directadmin/da-internal.sock ]; then
	${DA_PATH}/dataskq --custombuild
fi

#link things up for the lan.
#get the server IP
IP=$(curl --location --silent --connect-timeout 6 http://myip.directadmin.com 2>/dev/null)
LAN_IP=$(${DA_PATH}/scripts/get_main_ip.sh)

if [ "${IP}" != "" ] && [ "${LAN_IP}" != "" ]; then
	if [ "${IP}" != "${LAN_IP}" ]; then
		#Let us confirm that the LAN IP actually gives us the correct server IP.
		echo "Confirming that 'curl --location --silent --connect-timeout 6 --interface ${LAN_IP} http://myip.directadmin.com' returns ${IP} ..."
		EXTERNAL_IP=$(curl --location --silent --connect-timeout 6 --interface "${LAN_IP}" --disable --output - http://myip.directadmin.com 2>&1 || echo "")
		if [ -n "${EXTERNAL_IP}" ]; then
			#we got the IP WITH the bind
			if [ "${EXTERNAL_IP}" = "${IP}" ]; then
				echo "LAN IP SETUP: Binding to ${LAN_IP} did return the correct IP address.  Completing last steps of Auto-LAN setup ..."
				echo "Adding lan_ip=${LAN_IP} to directadmin.conf ..."
				${DA_PATH}/directadmin set lan_ip "${LAN_IP}"
				echo 'action=directadmin&value=restart' >> ${DA_TQ}

				echo "Linking ${LAN_IP} to ${IP}"
				NETMASK=$(grep -m1 ^netmask= ${SETUP_TXT} | cut -d= -f2)
				echo "action=linked_ips&ip_action=add&ip=${IP}&ip_to_link=${LAN_IP}&apache=yes&dns=no&apply=yes&add_to_ips_list=yes&netmask=${NETMASK}" >> ${DA_TQ}.cb
				${DA_PATH}/dataskq --custombuild
				
				echo "LAN IP SETUP: Done."
			else
				echo "*** scripts/install.sh: LAN: when binding to ${LAN_IP}, curl returned external IP ${EXTERNAL_IP}, which is odd."
				echo "Not automatically setting up the directadmin.conf:lan_ip=${LAN_IP}, and not automatically linking ${LAN_IP} to ${IP}"
				sleep 2
			fi
		fi
	fi
fi

if [ -e /etc/aliases ]; then
	if ! grep -q diradmin /etc/aliases; then
		echo "diradmin: :blackhole:" >> /etc/aliases
	fi
fi

if [ ! -e /bin/nice ]; then
	ln -s /usr/bin/nice /bin/nice
fi

if [ -s ${DACONF} ]; then
	echo ""
	echo "DirectAdmin should be accessible now";
	echo "If you cannot connect to the login URL, then it is likely that a firewall is blocking port 2222. Please see:"
	echo "  https://docs.directadmin.com/directadmin/general-usage/troubleshooting-da-service.html#cannot-connect-to-da-on-port-2222"
fi

if [ -z "${DA_SKIP_CUSTOMBUILD}" ]; then
	# Install CustomBuild
	if ! curl --location --progress-bar --output "${TMP_DIR}/custombuild.tar.gz" http://${DL_SERVER}/services/custombuild/2.0/custombuild.tar.gz || ! curl --location --progress-bar --output "${TMP_DIR}/custombuild.tar.gz" http://${BACKUP_DL_SERVER}/services/custombuild/2.0/custombuild.tar.gz; then
		echo "*** There was an error downloading the custombuild script. ***"
		exit 1
	fi
	tar xzf "${TMP_DIR}/custombuild.tar.gz" -C ${DA_PATH}
	chmod 755 "${DA_PATH}/custombuild/build"
	echo "CustomBuild installation has started, you may check the progress using the following command: tail -f ${DA_PATH}/custombuild/install.txt"
	if [ -n "${DA_INTERACTIVE_CUSTOMBUILD}" ] && [ ! -s /usr/local/directadmin/custombuild/options.conf ]; then
		${DA_PATH}/custombuild/build create_options
	elif [ -z "${DA_SKIP_SECURE_PHP}" ]; then
		/usr/local/directadmin/custombuild/build set secure_php yes > ${DA_PATH}/custombuild/install.txt 2>&1
	fi
	if [ ! -e /root/.skip_csf ] && [ -z "${DA_SKIP_CSF}" ]; then
		/usr/local/directadmin/custombuild/build set csf yes >> ${DA_PATH}/custombuild/install.txt 2>&1
	fi
	if [ ! -e /root/.using_fastest ] && [ ! -n "${DA_SKIP_FASTEST}" ]; then
		${DA_PATH}/custombuild/build set_fastest >> ${DA_PATH}/custombuild/install.txt 2>&1
	fi

	${DA_PATH}/custombuild/build update >> ${DA_PATH}/custombuild/install.txt 2>&1 &
	if [ -z "${DA_FOREGROUND_CUSTOMBUILD}" ]; then
		${DA_PATH}/custombuild/build all d >> ${DA_PATH}/custombuild/install.txt 2>&1 &
		echogreen "You will receive a message in the DirectAdmin panel when background installation finalizes."
	else
		${DA_PATH}/custombuild/build all d | tee ${DA_PATH}/custombuild/install.txt
	fi
fi

setDAChannel

echo ""
echo "The following information has been set:"
echo "Admin username: ${ADMIN_USER}"
echo "Admin password: ${ADMIN_PASS}"
echo "Admin email: ${EMAIL}"
echo ""
echo ""
echo "Server IP: ${EXTERNAL_IP}"
echo "Server Hostname: ${HOST}"
echo ""
echogreen "To login now, follow this URL: $(/usr/local/directadmin/directadmin --create-login-url user=${ADMIN_USER})"

printf \\a
sleep 1
printf \\a
sleep 1
printf \\a

exit 0
