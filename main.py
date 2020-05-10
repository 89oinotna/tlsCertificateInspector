import pyshark
from pyshark.packet.fields import LayerField, LayerFieldsContainer
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
from datetime import datetime
import sys

interface = 'eth0'  # interfaccia di rete
timeout = 0  # timeout per il live sniff
live = True
packet_count = 0  # numero pacchetti da ispezionare
file_path = ''  # percorso file pcap


class TLSCert:
    def __init__(self):
        self.not_before = None
        self.not_after = None
        self.issuer = []
        self.subject = []

    def add_issuer_sequence(self, seq):
        # field = [oid, seq]
        self.issuer.append(seq)

    def add_subject_sequence(self, seq):
        # field = [oid, seq]
        self.subject.append(seq)

    def add_not_before(self, time):
        self.not_before = datetime.strptime(time, '%y-%m-%d %H:%M:%S (%Z)')

    def add_not_after(self, time):
        self.not_after = datetime.strptime(time, '%y-%m-%d %H:%M:%S (%Z)')

    def isValid(self):
        now = datetime.now()
        if self.not_before > now or self.not_after < now:
            return False
        return True

    def isSelfSigned(self):
        if self.issuer == self.subject:
            return True
        return False

    def __str__(self):
        return "\tIssuer: " + str(self.issuer) + "\n\tSubject: " + str(self.subject) + "\n\tNot Before: " + str(
            self.not_before) + "\n\tNot After: " + str(self.not_after)


def get_all(field_container):
    """
    ritorna una lista contenente tutti i field di quel campo
    :param field_container:
    :return:
    """
    field_container: LayerFieldsContainer
    field_container = field_container.all_fields
    tmp = []
    field: LayerField
    for field in field_container:
        tmp.append(field.get_default_value())
    return tmp


def extract_certs(tls_layer):
    """
    Estrae i certificati da un paccketto
    :param tls_layer:
    :return:
    """
    cert_count = 0
    if_rdnSequence_count = []
    times = []
    af_rdnSequence_count = []
    rdn = []
    field_container: LayerFieldsContainer
    for field_container in list(tls_layer._all_fields.values()):  # prendo il field container per ogni campo
        field: LayerField
        field = field_container.main_field
        # controllo il nome del campo
        if field.name == 'x509if.RelativeDistinguishedName_item_element':
            rdn = (get_all(field_container))
        elif field.name == 'x509af.signedCertificate_element':
            cert_count = len(field_container.all_fields)
        elif field.name == 'x509if.rdnSequence':
            if_rdnSequence_count = (get_all(field_container))
        elif field.name == 'x509af.utcTime':
            times = get_all(field_container)
        elif field.name == 'x509af.rdnSequence':
            af_rdnSequence_count = get_all(field_container)
    certs = []
    for x in range(cert_count):
        cert = TLSCert()
        for y in range(int(if_rdnSequence_count[x])):
            cert.add_issuer_sequence(rdn.pop(0))
        for y in range(int(af_rdnSequence_count[x])):
            cert.add_subject_sequence(rdn.pop(0))
        cert.add_not_before(times.pop(0))
        cert.add_not_after(times.pop(0))
        certs.append(cert)

    return certs


def analyzePacket(packet):
    packet: Packet
    layer: Layer
    layer = packet.tls
    field: LayerFieldsContainer
    for cert in extract_certs(layer):
        if not cert.isValid():
            print(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Not Valid cert:\n', cert)
        if cert.isSelfSigned():
            print(packet.ip.src, packet.tcp.get_field_by_showname("Source Port"), 'Self Signed Cert:\n', cert)


if __name__ == "__main__":
    x = 1
    while x < len(sys.argv):
        arg = sys.argv[x]
        x += 1
        if arg == '-f':
            live = False
            file_path = sys.argv[x]
        elif arg == '-t':
            timeout = int(sys.argv[x])
        elif arg == '-pc':
            packet_count = int(sys.argv[x])
        elif arg == '-i':
            interface = sys.argv[x]
        else:
            raise Exception('Wrong argument format')
        x += 1

    if live:
        capture = pyshark.LiveCapture(interface=interface, display_filter='tls.handshake.certificate')
        capture.sniff(timeout=timeout)
        packet: Packet
        for packet in capture.sniff_continuously(packet_count):
            analyzePacket(packet)

    else:
        capture = pyshark.FileCapture(input_file=file_path, display_filter='tls.handshake.certificate')
        for packet in capture:
            analyzePacket(packet)
