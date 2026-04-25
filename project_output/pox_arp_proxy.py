"""POX controller module implementing controller-side ARP proxying."""

from datetime import datetime

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.revent import EventMixin


log = core.getLogger()

TRUSTED = {
    IPAddr("10.0.0.1"): EthAddr("00:00:00:00:00:01"),
    IPAddr("10.0.0.2"): EthAddr("00:00:00:00:00:02"),
    IPAddr("10.0.0.3"): EthAddr("00:00:00:00:00:03"),
}


def stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ArpProxy(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("POX ARP proxy loaded")

    def _send_arp_reply(self, event, request):
        trusted_mac = TRUSTED[request.protodst]
        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwsrc = trusted_mac
        reply.hwdst = request.hwsrc
        reply.protosrc = request.protodst
        reply.protodst = request.protosrc

        frame = ethernet(type=ethernet.ARP_TYPE, src=trusted_mac, dst=request.hwsrc)
        frame.set_payload(reply)

        msg = of.ofp_packet_out()
        msg.data = frame.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        msg.in_port = of.OFPP_NONE
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        arp_pkt = packet.find("arp")
        if arp_pkt is None:
            return

        verdict = "trusted"
        claimed_ip = arp_pkt.protosrc
        claimed_mac = arp_pkt.hwsrc

        if arp_pkt.opcode == arp.REQUEST:
            if arp_pkt.protodst in TRUSTED:
                log.info(
                    "[%s] ARP request src_ip=%s src_mac=%s target_ip=%s verdict=trusted",
                    stamp(),
                    claimed_ip,
                    claimed_mac,
                    arp_pkt.protodst,
                )
                self._send_arp_reply(event, arp_pkt)
            return

        if arp_pkt.opcode == arp.REPLY:
            if claimed_ip in TRUSTED and TRUSTED[claimed_ip] != claimed_mac:
                verdict = "dropped"
                log.warning(
                    "[%s] ARP reply src_ip=%s src_mac=%s verdict=%s",
                    stamp(),
                    claimed_ip,
                    claimed_mac,
                    verdict,
                )
                return

            log.info(
                "[%s] ARP reply src_ip=%s src_mac=%s verdict=%s",
                stamp(),
                claimed_ip,
                claimed_mac,
                verdict,
            )


def launch():
    core.registerNew(ArpProxy)
