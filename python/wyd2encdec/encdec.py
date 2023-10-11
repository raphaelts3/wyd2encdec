import struct


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

    def decrypt_pcap(self, path: str) -> bytes:
        raw = self._load_file(path)
        return bytes(raw)
