import struct

import arrow
from scapy.all import hexdump, rdpcap
from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw


class EncDec:
    _keys: bytes

    def __init__(self, keys_path: str) -> None:
        self._load_keys(keys_path)

    def _load_file(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def _load_keys(self, path: str) -> None:
        self._keys = self._load_file(path)

    @staticmethod
    def _op_add(a: int, b: int) -> int:
        return (a + b) & 255

    @staticmethod
    def _op_sub(a: int, b: int) -> int:
        return (a - b) & 255

    def _enc_dec(self, raw: list, _op_even, _op_odd) -> bytes:
        pos = 0
        while pos < len(raw):
            size = struct.unpack("<H", bytes(raw[pos : pos + 2]))[0]
            if size == 0xF311:
                # Hello
                pos += 4
                continue
            if size + pos > len(raw):
                print("Bad packet size at: ", pos)
                break
            key = self._keys[raw[pos + 2] << 1] & 255
            checksum_pre = 0
            checksum_pos = 0
            for i in range(4, size):
                mappedKey = self._keys[((key % 256) << 1) + 1]
                checksum_pre = (checksum_pre + raw[pos + i]) & 255
                match i & 3:
                    case 0:
                        raw[pos + i] = _op_even(raw[pos + i], (mappedKey << 1) & 255)
                    case 1:
                        raw[pos + i] = _op_odd(raw[pos + i], (mappedKey >> 3) & 255)
                    case 2:
                        raw[pos + i] = _op_even(raw[pos + i], (mappedKey << 2) & 255)
                    case 3:
                        raw[pos + i] = _op_odd(raw[pos + i], (mappedKey >> 5) & 255)
                checksum_pos = (checksum_pos + raw[pos + i]) & 255
                key += 1
            # print(
            #     "Checksums: ",
            #     checksum_pre,
            #     checksum_pos,
            #     (checksum_pre - checksum_pos) & 255,
            #     raw[pos + 3],
            # )
            pos += size
        return bytes(raw)

    def encrypt(self, path: str) -> bytes:
        raw = list(self._load_file(path))
        return self._enc_dec(raw, self._op_add, self._op_sub)

    def decrypt(self, path: str) -> bytes:
        raw = list(self._load_file(path))
        return self._enc_dec(raw, self._op_sub, self._op_add)

    @staticmethod
    def dump_pkt(pkt: Ether, data: bytes) -> str:
        size = len(data)
        if len(data) < 6:
            data += b"\x00" * (6 - len(data))
        return "[%d/%04X] 0x%04X %s (%s) : %s > %s\n" % (
            size,
            size,
            struct.unpack("<H", data[4:6])[0],
            arrow.get(pkt.time, tzinfo="UTC-3").format("YYYY-MM-DD HH:mm:ss"),
            arrow.get(pkt.time).humanize(),
            pkt.payload.src,
            pkt.payload.dst,
        )

    def decrypt_pcap(self, path: str) -> tuple[list[str], bytes]:
        pkts = rdpcap(path)
        raw = []
        dumps = []
        pkt: Ether
        prev_window = None
        for i, pkt in enumerate(pkts):
            if pkt.payload.payload.name != "TCP":
                continue
            payload: TCP = pkt.payload.payload
            # if (
            #     payload.dport != 8281 and payload.sport != 8281
            # ) or payload.payload.name != "Raw":
            if payload.payload.name != "Raw":
                continue
            raw_payload: Raw = payload.payload
            if len(raw_payload.load) >= 12:
                if prev_window is None or prev_window != payload.window:
                    prev_window = payload.window
                    raw.append({"pkt": pkt, "data": list(raw_payload.load)})
                else:
                    raw[-1]["data"] += list(raw_payload.load)
        decoded = bytes()
        for _pkt in raw:
            pkt = _pkt["pkt"]
            data = _pkt["data"]
            _decoded = self._enc_dec(data, self._op_sub, self._op_add)
            decoded += _decoded
            pos = 0
            while pos < len(data):
                size = struct.unpack("<H", bytes(_decoded[pos : pos + 2]))[0]
                if size == 0xF311:
                    size = 4
                __decoded = _decoded[pos : pos + size]
                dumps.append(EncDec.dump_pkt(pkt, __decoded) + hexdump(__decoded, True))
                pos += size
        return (dumps, decoded)
