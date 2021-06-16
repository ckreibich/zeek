#! /usr/bin/env python

import argparse
import configparser
import ipaddress
import json
import os.path
import subprocess
import sys
import uuid

ZEEKC_DEFAULT_CONTROLLER = '127.0.0.1:2150'
ZEEKC_CONTROLLER_TOPIC = 'zeek/cluster-control/controller'

try:
    import broker
except ImportError:
    try:
        res = subprocess.run(['zeek-config', '--python_dir'], capture_output=True)
    except subprocess.SubprocessError as err:
        print("Could not determine Zeek's Python folder via zeek-config: {}"
              .format(err))
        sys.exit(1)

    try:
        zeek_pydir = res.stdout.decode().strip()
    except UnicodeError:
        print('Cannot not decode directory "{}"'.format(res.stdout))
        sys.exit(1)

    if not os.path.isdir(zeek_pydir):
        print('Cannot access Zeek\'s Python directory "{}"'.format(zeek_pydir))
        sys.exit(1)

    sys.path.insert(0, zeek_pydir)
    import broker


# Broker's basic types aren't JSON-serializable, so patch that up:
def json_dumps(obj):
    def default(obj):
        if isinstance(obj, ipaddress.IPv4Address):
            return str(obj)
        if isinstance(obj, ipaddress.IPv6Address):
            return str(obj)
        if isinstance(obj, broker.Port):
            return str(obj)
        raise TypeError('cannot serialize %s (%s)', type(obj), str(obj))

    return json.dumps(obj, default=default)


# Wrapper around Broker's Event class to make it printable
class Event(broker.zeek.Event):
    def __str__(self):
        return self.name() + '(' + ', '.join([str(type(arg)) for arg in self.args()]) + ')'


class GetInstancesResponseEvent(Event):
    def requid(self):
        return self.args()[0]

    def instances(self):
        return self.args()[1]


class Controller:
    def __init__(self, controller_host, controller_port,
                 controller_topic=ZEEKC_CONTROLLER_TOPIC):
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.controller_topic = controller_topic
        self.ep = broker.Endpoint()
        self.sub = self.ep.make_subscriber(controller_topic)
        self.ssub = self.ep.make_status_subscriber(True)

    def connect(self):
        self.ep.peer(self.controller_host, self.controller_port, 0.0)

        # Wait until connection is established.
        status = self.ssub.get()

        if not (type(status) == broker.Status and status.code() == broker.SC.PeerAdded):
            print('error: could not connect to controller')
            return False

        return True

    def publish(self, event):
        self.ep.publish(self.controller_topic, event)

    def receive(self, event_class):
        topic, data = self.sub.get()
        return event_class(data)


def cmd_instances(controller, args):
    controller.publish(Event(
        'ClusterController::API::get_instances_request',
        str(uuid.uuid1())))
    resp = controller.receive(GetInstancesResponseEvent)

    print(json_dumps(resp.instances()))

def cmd_set_config(controller, args):
    pass

def main():
    parser = argparse.ArgumentParser(description='A zeekc prototype')
    parser.add_argument('--controller', metavar='HOST:PORT',
                        default=ZEEKC_DEFAULT_CONTROLLER,
                        help='Address and port of the controller '
                        '(default: {})'.format(ZEEKC_DEFAULT_CONTROLLER))

    command_parser = parser.add_subparsers(
        title='commands', dest='command',
        help='See `%(prog)s <command> -h` for per-command usage info.')
    command_parser.required = True

    sub_parser = command_parser.add_parser(
        'instances', help='Show instances connected to the controller.')
    sub_parser.set_defaults(run_cmd=cmd_instances)

    sub_parser = command_parser.add_parser(
        'set-config', help='Define data cluster layout')
    sub_parser.set_defaults(run_cmd=cmd_set_config)
    sub_parser.add_argument('-l', '--layout', metavar='FILE',
                            help='Cluster layout file')

    args = parser.parse_args()

    controller_parts = args.controller.split(':', 1)
    if len(controller_parts) != 2:
        print('error: controller must be a host:port tuple')
        sys.exit(1)

    controller_host = controller_parts[0]

    try:
        controller_port = int(controller_parts[1])
        if controller_port < 1 or controller_port > 65535:
            raise ValueError
    except ValueError:
        print('error: controller port number invalid')
        sys.exit(1)

    controller = Controller(controller_host, controller_port)
    if not controller.connect():
        sys.exit(1)

    args.run_cmd(controller, args)

    return 0

if __name__ == '__main__':
    sys.exit(main())
