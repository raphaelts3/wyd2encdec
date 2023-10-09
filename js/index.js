"use strict";

const { Command } = require("commander");
const EncDec = require("./encdec.js");
const program = new Command();

program
  .description("Encrypt/decrypt wyd2's packets")
  .argument("<keys>", "path to keys file")
  .argument("<command>", "'enc' for encrypt or 'dec' for decrypt")
  .argument("<encrypted>", "path to encrypted file")
  .argument("<decrypted>", "path to decrypted file")
  .action((keys, command, encrypted, decrypted) => {
    const instance = new EncDec(keys, encrypted, decrypted);
    if (command == "enc") {
      instance.encrypt();
    } else if (command == "dec") {
      instance.decrypt();
    }
  });

program.parse();
