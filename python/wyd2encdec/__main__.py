import asyncio
import logging
from pathlib import Path

import asyncclick as click
import click as sync_click

from .encdec import EncDec


@click.group()
def wyd2_run() -> None:
    ...


@wyd2_run.command(help="Decrypt a pcap file")
@click.argument("keys_path", type=str, required=True)
@click.argument("pcap_path", type=str, required=True)
def pcap(keys_path: str, pcap_path: str) -> None:
    logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]")
    instance = EncDec(keys_path)
    path = Path(pcap_path)
    paths = [path]
    if path.is_dir():
        paths = path.glob("*.pcap")
    for pcap_path in paths:
        path = Path(pcap_path)
        logging.info("Decrypting %s", path.name)
        dump, data = instance.decrypt_pcap(str(pcap_path))
        with open(path.with_name(f"{path.stem}_decoded.bin"), "wb") as f:
            f.write(data)
        with open(path.with_name(f"{path.stem}_decoded.txt"), "w") as f:
            f.write("\n\n".join(dump))


@sync_click.command()
@sync_click.argument("keys_path", type=str, required=True)
@sync_click.argument("operation", type=str, required=True)
@sync_click.argument("encrypted_path", type=str, required=True)
@sync_click.argument("decrypted_path", type=str, required=True)
def main(
    keys_path: str, operation: str, encrypted_path: str, decrypted_path: str
) -> None:
    logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]")
    instance = EncDec(keys_path)
    if operation == "enc":
        data = instance.encrypt(decrypted_path)
        with open("./encoded.bin", "wb") as f:
            f.write(data)
    elif operation == "dec":
        data = instance.decrypt(encrypted_path)
        with open("./decoded.bin", "wb") as f:
            f.write(data)


if __name__ == "__main__":
    # main()
    asyncio.run(pcap())
