#!/bin/bash



#########################################
##### Rundeck Configuration Script ######
#########################################

#
##
##
####
#####
###### The following script will fully provision your server 
###### with the latest Rundeck Enterprise Server
###### installing the required dependencies and packages. 
#####
####
###
##
#


#########################################
###### Edit the following Settings ######
#########################################


#MySQL root password. Set these to automate deployment (otherwise you will be prompted during install)
MYSQL_ROOT_PASS=

# Active Directory settings. Set these to automate deployment (otherwise you will be prompted during install)
AD_URL=
AD_BINDDN=
AD_BIND_PASS=
AD_BASE_DN=
AD_ROLE_DN=


###########################################
###### Do not edit below this line ########
###########################################

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

LOCAL_IP=$(ip addr | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')

function query_os () {

        if [ -f /etc/os-release ]; then
                # freedesktop.org and systemd
                . /etc/os-release
                OS=$ID
                VER=$VERSION_ID
        elif [ -f /etc/lsb-release ]; then
                # For some versions of Debian/Ubuntu without lsb_release command
                . /etc/lsb-release
                OS=$DISTRIB_ID
                VER=$DISTRIB_RELEASE
        elif [ -f /etc/debian_version ]; then
                # Older Debian/Ubuntu/etc.
                OS=debian
                VER=$(cat /etc/debian_version)
        elif [ -f /etc/redhat-release ]; then
                # Older Red Hat, CentOS, etc.
                 OS=$(cat /etc/redhat-release | head -1)
        else
                # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
                OS=$(uname -s)
                VER=$(uname -r)
        fi

}

function query_ram () {

	if [ -x "$(command -v dmidecode)" ]; then
		TOTAL_RAM=$(dmidecode -t 17 | grep "Size.*MB" | awk '{s+=$2} END {print s / 1024}')
	else
		TOTAL_RAM=$(awk '/MemTotal/ {print $2/(1024*1024)}' /proc/meminfo)
	fi

}

function rundeckd_start () {

        echo "Attempting to start Rundeck Enterprise. First start will initialize the database"
        echo "Please allow 60 seconds for initial start up to complete"
        systemctl start rundeckd
	max_iterations=15
	wait_seconds=6

	iterations=0
	while true
	do
		((iterations++))
		#echo "Attempt $iterations"
		sleep $wait_seconds

		RUNDECK_PORT=$(ss -anl | grep 4440)
		RUNDECK_PORT_STATUS=$?

		if [ "$RUNDECK_PORT_STATUS" -eq "0" ]; then
			echo "Rundeck server is active on port 4440. Please open your browser and go to..."
                        echo "http://$LOCAL_IP:4440 or, if you have configured a DNS record, http://rundeck1:4440"
			break
		fi

		if [ "$iterations" -ge "$max_iterations" ]; then
			echo "Rundeck Enterprise failed to start. Please check /var/log/rundeck/service.log for errors"
			exit 1
		fi
	done

}

function install_mysql_debian () {

	if [ -z "$MYSQL_ROOT_PASS" ]; then
		echo "Please input new MySQL root user password (please save this!)"
		while true; do
			read -s -p "New MySQL root Password: " MYSQL_ROOT_PASS
			echo
			read -s -p "New MySQL root Password (confirm): " MYSQL_ROOT_PASS_REQ
			echo
			[ "$MYSQL_ROOT_PASS" = "$MYSQL_ROOT_PASS_REQ" ] && break
			echo "Values do not match. Please try again"
		done
		
	fi	

	export DEBIAN_FRONTEND=noninteractive
	/usr/bin/debconf-set-selections <<< "mysql-apt-config mysql-apt-config/select-server select mysql-8.0"
	/usr/bin/debconf-set-selections <<< "mysql-apt-config mysql-apt-config/select-product select Ok"
	/usr/bin/debconf-set-selections <<< "mysql-community-server mysql-server/default-auth-override select Use Legacy Authentication Method (Retain MySQL 5.x Compatibility)"
	/usr/bin/debconf-set-selections <<< "mysql-community-server mysql-community-server/root-pass password $MYSQL_ROOT_PASS"
	/usr/bin/debconf-set-selections <<< "mysql-community-server mysql-community-server/re-root-pass password $MYSQL_ROOT_PASS"

	apt-get -qq update 
	wget -q -P TMP https://dev.mysql.com/get/mysql-apt-config_0.8.15-1_all.deb
	dpkg -i TMP/mysql-apt-config_0.8.15-1_all.deb
	apt-get -qq update 
	apt-get -y -qq install mysql-server mysql-client 
	systemctl enable mysql.service
	rm -fr TMP

	echo "[client]" >> /root/.my.cnf
	echo "user=root" >> /root/.my.cnf
	echo "password=$MYSQL_ROOT_PASS" >> /root/.my.cnf
	chmod 0600 /root/.my.cnf

	mysql -u root -e "DELETE FROM mysql.user WHERE User=''"
	mysql -u root -e "DELETE FROM mysql.db WHERE SUBSTR(db,4) = 'test'"
	mysql -u root -e "CREATE DATABASE rundeck"
	mysql -u root -e "CREATE USER 'rundeckuser'@'%' IDENTIFIED BY 'Restful718-Z'"
	mysql -u root -e "GRANT ALL ON rundeck.* TO 'rundeckuser'@'%' WITH GRANT OPTION"
	mysql -u root -e "FLUSH PRIVILEGES"
}

function install_rundeck_debian () {

	dpkg -s rundeckpro-enterprise &> /dev/null
        RETVAL=$?

        if [ $RETVAL -ne 0 ]; then
		echo "Installing Rundeck Enterprise. Please allow 40-60 seconds to complete"
		apt-get -qq update 
		apt-get -y -qq install curl uuid-runtime 
		DEB_PACKAGE=$(curl -s https://download.rundeck.com/eval/| grep -Eo "(http|https)://rundeckpro.bintray.com/deb/.[a-zA-Z0-9./?=_-]*.deb")
		mkdir TMP
		echo "Downloading Rundeck Enterprise"
		wget -q -P TMP $DEB_PACKAGE 
		dpkg -i TMP/*.deb
		rm -fr TMP
		systemctl enable rundeckd.service
	else
		echo "Rundeck Enterprise already installed, continuing"
	fi
}

function install_openjdk8_debian () {
	
	apt-get -y -qq install gnupg
	wget -qO - https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | apt-key add -
	apt-get -y -qq install software-properties-common 
	add-apt-repository --yes https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/
	apt-get -qq update
	apt-get -qq -y install adoptopenjdk-8-hotspot adoptopenjdk-8-hotspot-jre
}

function mysql_local () {

	sed -e '/dataSource.url/ s/^#*/#/' -i /etc/rundeck/rundeck-config.properties
	sed -e "/dataSource.url/a \ \ndataSource.url = jdbc:mysql://localhost/rundeck?autoReconnect=true&useSSL=false\ndataSource.username=rundeckuser\ndataSource.password=Restful718-Z\ndataSource.driverClassName=com.mysql.jdbc.Driver" -i /etc/rundeck/rundeck-config.properties

}

function update_grails_url () {

	if ! [ -z $LOCAL_IP ]; then
		sed -e "s/grails.serverURL=http:\/\/localhost:4440/grails.serverURL=http:\/\/$LOCAL_IP:4440/" -i /etc/rundeck/rundeck-config.properties
	else 
		echo "not able to detect local IP to configure rundeck-config.properties"
	fi

}

function mysql_remote () {

	if [[ -z $REMOTE_MYSQL_HOST || -z $REMOTE_MYSQL_USER || -z $REMOVE_MYSQL_PASSWORD ]]; then
		echo "MySQL configuration for remote host. User must have proper database permissions"
		echo "https://docs.rundeck.com/docs/administration/configuration/database/mysql.html#setup-rundeck-database"
		echo "Input MySQL DNS/IP Address [Example mysql.corp.com OR 10.10.10.7]"
		read REMOTE_MYSQL_HOST
		echo "Input MySQL user"
		read REMOTE_MYSQL_USER
		echo "Input MySQL password"
		read REMOTE_MYSQL_PASSWORD
	fi
	sed -e '/dataSource.url/ s/^#*/#/' -i /etc/rundeck/rundeck-config.properties
	sed -e "/dataSource.url/a \ \ndataSource.url = jdbc:mysql://$REMOTE_MYSQL_HOST/rundeck?autoReconnect=true&useSSL=false\ndataSource.username=$REMOTE_MYSQL_USER\ndataSource.password=$REMOTE_MYSQL_PASSWORD\ndataSource.driverClassName=com.mysql.jdbc.Driver" -i /etc/rundeck/rundeck-config.properties

}

function ldap_setup () {

	sed -e "/grails.serverURL/a \ \nrundeck.security.syncLdapUser=true" -i /etc/rundeck/rundeck-config.properties
	echo "Configuring Rundeck Enterprise integration to Active Directory"
	echo "Read the documentation for AD/LDAP configuration requirements:"
	echo "https://docs.rundeck.com/docs/administration/security/authentication.html#ldap"
	if [[ -z $AD_URL || -z $AD_BINDDN || -z $AD_BIND_PASS || -z $AD_BASE_DN || -z AD_ROLE_DN ]]; then
		echo "Type the IP or DNS name of ONE of your domain controllers (e.g. dc01)"
		read AD_URL
		echo "Type the full path of ActiveDirectory bindDN (e.g. cn=rundeck-lookup,ou=My-users,dc=mydomain,dc=local)"
		read AD_BINDDN
		while true; do
                        read -s -p "AD Bind Password: " AD_BIND_PASS
                        echo
                        read -s -p "AD Bind Password (confirm): " AD_BIND_PASS_REQ
                        echo
                        [ "$AD_BIND_PASS" = "$AD_BIND_PASS_REQ" ] && break
                        echo "Values do not match. Please try again"
                done
		echo "Type the base search path of your users (e.g. ou=My-users,dc=mydomain,dc=local)"
		read AD_BASE_DN
		echo "Type the base search path of your groups (e.g. ou=My-groups,dc=flubber,dc=us)"
		read AD_ROLE_DN
	fi
	cat  > /etc/rundeck/jaas-ldap.conf <<EOF
	activedirectory {
		com.dtolabs.rundeck.jetty.jaas.JettyCachingLdapLoginModule required
		debug="true"
		contextFactory="com.sun.jndi.ldap.LdapCtxFactory"
		providerUrl="ldap://$AD_URL:389"
		bindDn="$AD_BINDDN"
		bindPassword="$AD_BIND_PASS"
		authenticationMethod="simple"
		forceBindingLogin="true"
		userBaseDn="$AD_BASE_DN"
		userRdnAttribute="sAMAccountName"
		userIdAttribute="sAMAccountName"
		userPasswordAttribute="unicodePwd"
		userObjectClass="user"
		roleBaseDn="$AD_ROLE_DN"
		roleNameAttribute="cn"
		roleMemberAttribute="member"
		roleObjectClass="group"
		cacheDurationMillis="300000"
		reportStatistics="true"
		userLastNameAttribute="sn"
		userFirstNameAttribute="givenName"
		userEmailAttribute="mail";
		};
EOF

	chown rundeck:rundeck /etc/rundeck/jaas-ldap.conf

	if [ -d "/etc/sysconfig" ]; then
		#CentOS/RHEL
		echo '"RDECK_JVM_OPTS="-Drundeck.jaaslogin=true -Djava.security.auth.login.config=/etc/rundeck/jaas-ldap.conf -Dloginmodule.name=ldap"' > /etc/sysconfig/rundeckd
		chown root:root /etc/sysconfig/rundeckd
	else
		#Debian/Ubuntu
		echo 'RDECK_JVM_OPTS="-Drundeck.jaaslogin=true -Djava.security.auth.login.config=/etc/rundeck/jaas-ldap.conf -Dloginmodule.name=activedirectory"' > /etc/default/rundeckd
		chown root:root /etc/default/rundeckd
	fi

}

function check_mysql_installed_debian () {
	dpkg -s mysql-server &> /dev/null
	RETVAL=$?

	if [ $RETVAL -ne 0 ]; then

		while true; do
			read -p "MySQL Server not installed. Would you like to install it? (y|n)" yn
		    case $yn in
			[Yy]* ) install_mysql_debian;echo "Installing and configuring latest MySQL Server, please allow 40-60 seconds";break;;
			[Nn]* ) echo "MySQL Server required, exiting"; exit;;
			* ) echo "Please answer yes or no.";;
		    esac
		done
	fi
}

function check_openjdk_installed () {
	if type -p java; then
	    echo "Java installed, continuing"
	    _java=java
	elif [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]];  then
	    echo "Java installed, continuing"
	    _java="$JAVA_HOME/bin/java"
	else
	    echo "Java not detected, installing";
	query_os

	    if [[ "$OS" =~ [Dd]ebian ]]; then
	        if [[ "$VERSION_ID" -eq 9 ]]; then
		    apt-get -qq update 
	    	    apt-get -y -qq install openjdk-8-jdk openjdk-8-jdk
	        else
	    	    install_openjdk8_debian
	        fi

	    fi
	fi
}



cat <<'EOF' 
  _____                 _           _      _____           _        _ _           
 |  __ \               | |         | |    |_   _|         | |      | | |          
 | |__) _   _ _ __   __| | ___  ___| | __   | |  _ __  ___| |_ __ _| | | ___ _ __ 
 |  _  | | | | '_ \ / _` |/ _ \/ __| |/ /   | | | '_ \/ __| __/ _` | | |/ _ | '__|
 | | \ | |_| | | | | (_| |  __| (__|   <   _| |_| | | \__ | || (_| | | |  __| |   
 |_|  \_\__,_|_| |_|\__,_|\___|\___|_|\_\ |_____|_| |_|___/\__\__,_|_|_|\___|_|   
EOF
                                                                                  
                                                                                  
## Prerequisite Check

#Determine OS type
query_os

if [[ "$OS" =~ [Dd]ebian ]]; then
        if [[ "$VERSION_ID" -gt 8 ]]; then
                echo "$OS version $VERSION_ID detected, continuing"
        else
                echo "$OS version $VERSION_ID not supported, exiting"
                exit
        fi
else
	echo "Detected OS $OS is not currently supported, exiting"
	exit
fi


#Determine Total RAM
query_ram


#Prompt user if they would like to continue the install
while true; do
	read -p "This will install Rundeck Enterprise, including Java and MySQL if desired. Continue (y|n)?" yn
		case $yn in
			[Yy]* ) break;;
			[Nn]* ) echo "Aborting install"; exit;;
			* ) echo "Please answer yes or no.";;
		esac
done


if [ "$TOTAL_RAM" -gt 2 ]; then
	echo "$TOTAL_RAM GB detected, continuing"
else
	echo "$TOTAL_RAM GB does not satisfy requirements, exiting"
	exit
fi

## Check for packages and install
check_openjdk_installed
install_rundeck_debian


cat <<'EOF'
  __  __        _____  ____  _         _____             __ _                       _   _             
 |  \/  |      / ____|/ __ \| |       / ____|           / _(_)                     | | (_)            
 | \  / |_   _| (___ | |  | | |      | |     ___  _ __ | |_ _  __ _ _   _ _ __ __ _| |_ _  ___  _ __  
 | |\/| | | | |\___ \| |  | | |      | |    / _ \| '_ \|  _| |/ _` | | | | '__/ _` | __| |/ _ \| '_ \ 
 | |  | | |_| |____) | |__| | |____  | |___| (_) | | | | | | | (_| | |_| | | | (_| | |_| | (_) | | | |
 |_|  |_|\__, |_____/ \___\_|______|  \_____\___/|_| |_|_| |_|\__, |\__,_|_|  \__,_|\__|_|\___/|_| |_|
          __/ |                                                __/ |                                  
         |___/                                                |___/                                   
EOF


while true; do
	read -p "Would you like to install MySQL server locally or use a remote MySQL server? ("l" for local | "r" for remote)" lr
		case $lr in
			[Ll]* ) echo "Configuring Rundeck for local MySQL server";check_mysql_installed_debian;mysql_local; break;;
			[Rr]* ) echo "Configuring Rundeck for remote MySQL server";mysql_remote; break;;
			* ) echo "Please answer l or r.";;
		esac
done

cat <<'EOF'
           _____     _____             __ _                       _   _
     /\   |  __ \   / ____|           / _(_)                     | | (_)
    /  \  | |  | | | |     ___  _ __ | |_ _  __ _ _   _ _ __ __ _| |_ _  ___  _ __
   / /\ \ | |  | | | |    / _ \| '_ \|  _| |/ _` | | | | '__/ _` | __| |/ _ \| '_ \
  / ____ \| |__| | | |___| (_) | | | | | | | (_| | |_| | | | (_| | |_| | (_) | | | |
 /_/    \_|_____/   \_____\___/|_| |_|_| |_|\__, |\__,_|_|  \__,_|\__|_|\___/|_| |_|
                                             __/ |
                                            |___/

EOF

while true; do
	read -p "Configure Rundeck with LDAP/Active Directory authentication? (y|n)" yn
                case $yn in
                        [Yy]* ) echo "Configuring Rundeck for LDAP authentication";ldap_setup; break;;
                        [Nn]* ) echo "Skipping LDAP authentication"; break;;
                        * ) echo "Please answer y or n.";;
                esac
done

cat <<'EOF'



  _____           _        _ _       _   _                _____                      _      _           _
 |_   _|         | |      | | |     | | (_)              / ____|                    | |    | |         | |
   | |  _ __  ___| |_ __ _| | | __ _| |_ _  ___  _ __   | |     ___  _ __ ___  _ __ | | ___| |_ ___  __| |
   | | | '_ \/ __| __/ _` | | |/ _` | __| |/ _ \| '_ \  | |    / _ \| '_ ` _ \| '_ \| |/ _ | __/ _ \/ _` |
  _| |_| | | \__ | || (_| | | | (_| | |_| | (_) | | | | | |___| (_) | | | | | | |_) | |  __| ||  __| (_| |
 |_____|_| |_|___/\__\__,_|_|_|\__,_|\__|_|\___/|_| |_|  \_____\___/|_| |_| |_| .__/|_|\___|\__\___|\__,_|
                                                                              | |
                                                                              |_|
EOF

#Update /etc/rundeck/rundeck-config.properties with local IP
update_grails_url


#Start rundeck and check if it is active and listening on port 4440
rundeckd_start
