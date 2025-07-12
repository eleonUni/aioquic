import argparse
import asyncio
import logging
import struct
from typing import Dict, Optional

import time
import jwt
import base64

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import SessionTicket
from dnslib.dns import DNSRecord

from dnslib import DNSHeader, RR, QTYPE, TXT, A
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

with open("/home/user/resolver_private.pem", "rb") as f:
    RESOLVER_PRIVATE_KEY = RSA.import_key(f.read())
with open("/home/user/proxy_public.pem", "rb") as f:
    PROXY_PUBLIC_KEY = RSA.import_key(f.read())
    PROXY_CIPHER = PKCS1_OAEP.new(PROXY_PUBLIC_KEY) #initialisation chifreur RSQ qvec pqdding
    
class DnsServerProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            # parse query
            length = struct.unpack("!H", bytes(event.data[:2]))[0]
            query = DNSRecord.parse(event.data[2 : 2 + length])
            # if client provide add records, retrrieve them
            ar = query.ar
            # drop records if further interaction with unmodified resolvers
            query.ar = []

            # log
            print("Requete recue")
            print("Questions", query.questions)
            print("Additional Records", ar)

            # create token
            qname = str(query.q.qname)
            client_ip = self._quic._network_paths[0].addr[0]
            resolver_cid = self._quic.host_cid.hex()
            timestamp = int(time.time())

            payload = {
                "client_ip": client_ip,
                "resolver_cid": resolver_cid,
                "timestamp": timestamp,
                "service_name": qname
            }

            # sign and encrypt token
            signed_jwt = jwt.encode(payload, RESOLVER_PRIVATE_KEY.export_key(), algorithm="RS256")
            
            # AES key + iv
            aes_key = get_random_bytes(32)  # 256 bits
            iv = get_random_bytes(16)

            # Encrypt JWT with AES
            aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ciphertext = aes_cipher.encrypt(pad(signed_jwt.encode(), AES.block_size))

            # Encrypt AES key with RSA
            encrypted_key = PROXY_CIPHER.encrypt(aes_key)

            # Final token = concat(encrypted_key || iv || ciphertext)
            final_token = encrypted_key + iv + ciphertext

            # perform lookup and serialize answer
            #data = query.send(args.resolver, 53)
            #parse answer
            #response = DNSRecord.parse(data)

            response = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
            
            response.add_answer(RR(
                rname=query.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=10,
                rdata=A("192.168.1.2"),  # IP du proxy maquiche
            ))

            token_b64 = base64.b64encode(final_token).decode()
            chunks= [token_b64[i:i+255] for i in range(0, len(token_b64), 255)]

            # create response with additional data
            response.ar.append(RR(
                rname="auth",
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=10,
                rdata=TXT(*chunks),
            ))

            data = response.pack()
            data = struct.pack("!H", len(data)) + data

            # send answer
            self._quic.send_stream_data(event.stream_id, data, end_stream=True)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


async def main(
    host: str,
    port: int,
    configuration: QuicConfiguration,
    session_ticket_store: SessionTicketStore,
    retry: bool,
) -> None:
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=DnsServerProtocol,
        session_ticket_fetcher=session_ticket_store.pop,
        session_ticket_handler=session_ticket_store.add,
        retry=retry,
    )
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS over QUIC server")
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=853,
        help="listen on the specified port (defaults to 853)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--resolver",
        type=str,
        default="8.8.8.8",
        help="Upstream Classic DNS resolver to use",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # create QUIC logger
    if args.quic_log:
        quic_logger = QuicFileLogger(args.quic_log)
    else:
        quic_logger = None

    configuration = QuicConfiguration(
        alpn_protocols=["doq"],
        is_client=False,
        quic_logger=quic_logger,
    )

    configuration.load_cert_chain(args.certificate, args.private_key)

    try:
        asyncio.run(
            main(
                host=args.host,
                port=args.port,
                configuration=configuration,
                session_ticket_store=SessionTicketStore(),
                retry=args.retry,
            )
        )
    except KeyboardInterrupt:
        pass
