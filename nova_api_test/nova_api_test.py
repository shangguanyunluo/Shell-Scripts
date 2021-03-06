import getopt
import logging

import time

import sys

import aexpect
from exceptions import Exception
import openstack_utils

image_name = "ubuntu"
vm_name = "cloud_test"
flavor_name = "yardstick-pktgen-dpdk.flavor"
key_name = "zyf_key"
network_name = "cloudtest_net"
security_groups = ["28fb1da7-f040-4edb-b435-63795eabc976"]
username = 'root'


def create_vm(image_name=image_name, vm_name=vm_name, flavorname=flavor_name,
              network_name=network_name, security_groups=security_groups):
    neutronclient = openstack_utils.get_neutron_client()

    print("Prepare to create vm named:%s" % vm_name)

    image = openstack_utils.get_image_by_name(name=image_name)

    network_id = openstack_utils.get_network_id(neutronclient, network_name)
    openstack_utils.create_instance_and_wait_for_active(flavor_name=flavorname,
                                                        image_id=image.id,
                                                        network_id=network_id,
                                                        instance_name=vm_name,
                                                        key_name=key_name,
                                                        security_groups=security_groups)
    print("Success to %s vm:%s" % ("create", vm_name))


def assign_floating_ip_to_vm(vm_name=vm_name, fip_list=None):
    print("Prepare to add floating ip to vm:%s" % vm_name)
    if not fip_list:
        fip_list = openstack_utils.get_free_floating_ips()

    assigned_ips = []
    vm = find_vm_from_name(vm_name)
    if vm.addresses:
        assigned_ips = [address for address in vm.addresses.values()[0]
                        if address[u'OS-EXT-IPS:type'] == u'floating']
    if len(assigned_ips) < 1:
        free_ip = fip_list[-1].get('floating_ip_address')
        vm.add_floating_ip(free_ip)
        print("Assigned floating IP '%s' to VM '%s'" % (free_ip, vm.name))
        return free_ip
    return assigned_ips[0]


def login_vm(vm_ip=None, username=username, password=None, timeout=360):
    print("Prepare to login vm:%s." % vm_ip)
    cmd = 'whoami'
    use_key = password is None
    end_time = time.time() + timeout
    responsive = False
    while time.time() < end_time:
        if responsive:
            return True
        try:
            session = openstack_utils.RemoteRunner(host=vm_ip,
                                                   username=username,
                                                   password=password,
                                                   use_key=use_key,
                                                   timeout=timeout)
            if not session:
                continue
            result = session.run(cmd)
            print("%s output is : %s" % (cmd, result))
            if username in result.stdout:
                responsive = True
        except Exception, e:
            print('Failed to login vm: %s' % e)
            continue
    print("Success to login vm:%s." % vm_ip)
    return responsive


def find_vm_from_name(vm_name=None):
    novaclient = openstack_utils.get_nova_client()
    server_client = novaclient.servers
    vms = server_client.findall(name=vm_name)
    if not vms:
        print("Did not find VM %s" % vm_name)
        return None
    return vms[0]


def del_vm(name=vm_name):
    print("Try to delete vm %s" % name)
    _vm = find_vm_from_name(name)
    if _vm is not None:
        _vm.delete()
        print("Success to %s vm:%s" % ("delete", name))


def stop_vm(name=vm_name):
    print("Prepare to %s vm:%s" % ("stop", name))
    _vm = find_vm_from_name(name)
    _vm.stop()
    if wait_for_vm_in_status(_vm, 'SHUTOFF'):
        print("Success to %s vm:%s" % ("stop", name))
    else:
        print("Fail to %s vm:%s" % ("stop", name))


def start_vm(name=vm_name):
    print("Prepare to %s vm:%s" % ("start", name))
    _vm = find_vm_from_name(name)
    _vm.start()
    if wait_for_vm_in_status(_vm, 'ACTIVE'):
        print("Success to %s vm:%s" % ("start", name))
    else:
        print("Fail to %s vm:%s" % ("start", name))


def wait_for_vm_in_status(vm, status, step=3, timeout=360,
                          delete_on_failure=False):
    end_time = time.time() + timeout

    while time.time() < end_time:
        _vm = find_vm_from_name(vm.name)
        print("VM (ID:%s Name:%s) in status: %s" % (_vm.id, _vm.name,
                                                    _vm.status))
        if _vm.status == status:
            return True

        if _vm.status == 'ERROR':
            logging.error(
                "VM ID: %s name: %s in status ERROR!!" % (_vm.id, _vm.name))
            if delete_on_failure:
                _vm.delete()
            return False

        time.sleep(step)
    else:
        logging.error("VM (ID: %s name: %s) still not in status: %s"
                      % (_vm.id, _vm.name, status))
        return False


def operations_of_vm():
    create_vm()
    time.sleep(2)
    ip = assign_floating_ip_to_vm()
    time.sleep(2)
    login_vm(vm_ip=ip)
    time.sleep(2)
    stop_vm()
    time.sleep(5)
    start_vm()
    time.sleep(5)
    del_vm()


def usage():
    _doc_ = """
    -c   --create : create a vm;
    -s   --start  : start a vm which is stoped;
    -d   --delete : delete a vm;
    -a   --add_fip: add floating ip to vm;
    -S   --stop   : stop a vm which is running;
    -A   --AllOperation : all operations about vm.
    """
    print(_doc_)


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "csdaSAl:",
                                   ["create", "start", "delete", "add_fip",
                                    "stop", "AllOperation"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    method = None
    for opt, arg in opts:
        if opt in ("-c", "--create"):
            method = create_vm
        elif opt in ("-s", '--start'):
            method = start_vm
        elif opt in ('-S', '--stop'):
            method = stop_vm
        elif opt in ("-d", "--delete"):
            method = del_vm
        elif opt in ("-a", "--add_fip"):
            method = assign_floating_ip_to_vm
        elif opt in ("-A", "--AllOperation"):
            method = operations_of_vm
        elif opt == '-l':
            login_vm(vm_ip=arg)
            sys.exit(0)

    method()


if __name__ == '__main__':
    main(sys.argv[1:])
