#!/bin/bash

manage_network_vip='10.100.46.150'
public_network_vip='10.100.46.150'
controller_public_ip='10.100.46.105'
controller_name_list=('controller-1' 'controller-2' 'controller-3')
controller_public_ip_list=('10.100.46.105' '10.100.46.105' '10.100.46.105')
controller_ip_list=('192.168.0.186' '192.168.0.185' '192.168.0.187')
controller_pwd='lenovo'


function controller_ssh_without_pwd(){
    sshpass -p ${controller_pwd} ssh -o StrictHostKeyChecking=no root@${controller_public_ip}  "
hostname
ssh-keygen -t rsa -N '' -f id_rsa -q;
echo Generate Public key status:$?;

ssh-copy-id ${controller_ip_list[1]};
#echo ssh-copy-id ${controller_ip_list[1]} status:$?;

"
}

function controller_env_prepare(){
    ###clear
    controller_num_1=$1
    echo controller_num_1=$1
    controller_num_2=`expr $1 + 1`
    controller_num_2=`expr $controller_num_2 % 3`
    echo controller_num_2=$controller_num_2
    controller_num_3=`expr $1 + 2`
    controller_num_3=`expr $controller_num_3 % 3`
    echo controller_num_3=$controller_num_3
    sshpass -p ${controller_pwd} ssh -tt -o StrictHostKeyChecking=no root@${controller_public_ip_list[$1]}  <<EOF
hostnamectl set-hostname ${controller_name_list[$1]}  #step2
timedatectl set-timezone Asia/Shanghai;  #step 3l
echo timedatectl set status:$?;
#step 4
systemctl stop firewalld
systemctl disable firewalld
cat /etc/sysconfig/selinux| grep -E '^SELINUX='
sed -i 's/^SELINUX=\w*/SELINUX=disabled/g' /etc/sysconfig/selinux
cat /etc/sysconfig/selinux| grep -E '^SELINUX='
getenforce
echo getenforce status:$?;

#step 5:vim /etc/hosts
###\cp -f /etc/hosts.backup /etc/hosts
sed -i "s/^127.0.0.1 .*$/& ${controller_name_list[$1]}/g" /etc/hosts;
sed -i "s/^::1 .*$/& ${controller_name_list[$1]}/g" /etc/hosts;
echo "${manage_network_vip} api.inte.lenovo.com" >> /etc/hosts;
echo "${manage_network_vip} controller" >> /etc/hosts;
echo "${controller_ip_list[${controller_num_2}]} ${controller_name_list[${controller_num_2}]}" >> /etc/hosts;
echo "${controller_ip_list[${controller_num_3}]} ${controller_name_list[${controller_num_3}]}" >> /etc/hosts;
exit
EOF
}

function controller_env_prepare2(){
    ###clear
    controller_num_1=$1
    echo controller_num_1=$1
    controller_num_2=`expr $1 + 1`
    controller_num_2=`expr $controller_num_2 % 3`
    echo controller_num_2=$controller_num_2
    controller_num_3=`expr $1 + 2`
    controller_num_3=`expr $controller_num_3 % 3`
    echo controller_num_3=$controller_num_3
    #sshpass -p ${controller_pwd} 
    ssh -tt -o StrictHostKeyChecking=no root@${controller_ip_list[$1]}  <<EOF
hostnamectl set-hostname ${controller_name_list[$1]}  #step2
timedatectl set-timezone Asia/Shanghai;  #step 3l
echo timedatectl set status:$?;
#step 4
systemctl stop firewalld
systemctl disable firewalld
cat /etc/sysconfig/selinux| grep -E '^SELINUX='
sed -i 's/^SELINUX=\w*/SELINUX=disabled/g' /etc/sysconfig/selinux
cat /etc/sysconfig/selinux| grep -E '^SELINUX='
getenforce
echo getenforce status:$?;

#step 5:vim /etc/hosts
###\cp -f /etc/hosts.backup /etc/hosts
sed -i "s/^127.0.0.1 .*$/& ${controller_name_list[$1]}/g" /etc/hosts;
sed -i "s/^::1 .*$/& ${controller_name_list[$1]}/g" /etc/hosts;
echo "${manage_network_vip} api.inte.lenovo.com" >> /etc/hosts;
echo "${manage_network_vip} controller" >> /etc/hosts;
echo "${controller_ip_list[${controller_num_2}]} ${controller_name_list[${controller_num_2}]}" >> /etc/hosts;
echo "${controller_ip_list[${controller_num_3}]} ${controller_name_list[${controller_num_3}]}" >> /etc/hosts;
exit
EOF
}

function ha_env_prepare(){
    for i in $(seq 3)
    do
        let index=$i-1
        controller_env_prepare2 $index
    done
}

#controller_ssh_without_pwd
ha_env_prepare

