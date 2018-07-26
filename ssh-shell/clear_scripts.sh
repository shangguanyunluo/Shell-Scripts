#! /bin/bash

clear(){

server_ip_list=('192.168.1.6' '192.168.1.5')

echo "server list is : "${server_ip_list[@]}

cmd_install="yum install -y sshpass"
cmd_clear="sh /etc/ceph/scripts/clear.sh"
cmd_stopctdb="systemctl stop ctdb"
cmd_ctdb="ps -ef | grep ctdb | awk '{print \$2}'| xargs -I {} kill -9 {}"
cmd_mount="mount | grep f2fs | awk '{print \$3}'"
cmd_umount="mount | grep f2fs | awk '{cmd=\"umount \"\$3;system(cmd)}'"
var_sshpass=$(rpm -qa sshpass)
node_pwd=123456

if [ -z $var_sshpass ]
then
    ${cmd_install}
else
    echo "sshpass has installed."
fi

for server_ip in ${server_ip_list[@]}
do
    # sh clear.sh
    echo "--------------------Start execute clear.sh--------------"
    sshpass -p ${node_pwd} ssh -tt -o "StrictHostKeyChecking no" root@${server_ip} <<EOF
        ${cmd_stopctdb}
        ${cmd_ctdb}
        ${cmd_clear}
        exit
EOF
    echo "-------------------Finished to execute clear.sh------------------"

    cmd_mount='mount | grep f2fs | grep -o -E "/Ceph(/\w+)+(-\w+)+"'
    sshpass -p ${node_pwd} ssh -tt -o 'StrictHostKeyChecking no'  root@${server_ip} ${cmd_mount}


    if [ $? -eq 1 ]
    then
        echo "There is nothing to clear."
    else
        echo '------------------------------'
        sshpass -p ${node_pwd} ssh -o 'StrictHostKeyChecking no' root@${server_ip} ${cmd_umount}
        echo '===================='
    fi
done
}

clear
