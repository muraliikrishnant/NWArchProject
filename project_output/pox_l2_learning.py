"""Standalone POX reactive L2 learning switch vulnerable to ARP poisoning."""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.revent import EventMixin


log = core.getLogger()


class LearningSwitch(EventMixin):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)

    def _install(self, packet, port):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        in_port = event.port
        self.mac_to_port[packet.src] = in_port

        arp_pkt = packet.find("arp")
        if arp_pkt is not None:
            log.info(
                "ARP observed: opcode=%s src_ip=%s src_mac=%s dst_ip=%s ingress=%s",
                "reply" if arp_pkt.opcode == arp.REPLY else "request",
                arp_pkt.protosrc,
                arp_pkt.hwsrc,
                arp_pkt.protodst,
                in_port,
            )
            # Intentionally vulnerable behavior: the controller does not validate
            # ARP claims and simply learns from traffic it receives.

        if packet.dst.is_multicast or packet.dst not in self.mac_to_port:
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = in_port
            self.connection.send(msg)
            return

        out_port = self.mac_to_port[packet.dst]
        self._install(packet, out_port)

        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = in_port
        self.connection.send(msg)


class L2LearningController(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("POX L2 learning controller loaded on 6633")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", event.connection)
        LearningSwitch(event.connection)


def launch():
    core.registerNew(L2LearningController)
