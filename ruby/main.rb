#!/usr/bin/env ruby

require 'packetfu'

class EncDec
  def initialize(keys_path)
    @keys = load_file(keys_path)
  end

  def load_file(path)
    File.open(path, 'rb') { |f| f.read }
  end

  def op_add(a, b)
    (a + b) & 255
  end

  def op_sub(a, b)
    (a - b) & 255
  end

  def enc_dec(raw, op_even, op_odd)
    pos = 0
    while pos < raw.length
      size = raw[pos, 2].unpack('v').first
      key = @keys[raw[pos + 2] << 1] & 255
      checksum_pre = 0
      checksum_pos = 0

      (4...size).each do |i|
        mapped_key = @keys[((key % 256) << 1) + 1]
        checksum_pre = (checksum_pre + raw[pos + i]) & 255

        case i & 3
        when 0
          raw[pos + i] = op_even.call(raw[pos + i], (mapped_key << 1) & 255)
        when 1
          raw[pos + i] = op_odd.call(raw[pos + i], (mapped_key >> 3) & 255)
        when 2
          raw[pos + i] = op_even.call(raw[pos + i], (mapped_key << 2) & 255)
        when 3
          raw[pos + i] = op_odd.call(raw[pos + i], (mapped_key >> 5) & 255)
        end

        checksum_pos = (checksum_pos + raw[pos + i]) & 255
        key += 1
      end

      pos += size
    end

    raw.pack('C*')
  end

  def encrypt(path)
    raw = load_file(path).bytes
    enc_dec(raw, method(:op_add), method(:op_sub))
  end

  def decrypt(path)
    raw = load_file(path).bytes
    enc_dec(raw, method(:op_sub), method(:op_add))
  end

  def self.dump_pkt(pkt, data)
    len = data.length
    "[%d/%04X] 0x%04X %s (%s) : %s > %s\n" % [
      len,
      len,
      data[4, 2].unpack('v').first,
      Time.now.strftime("%Y-%m-%d %H:%M:%S"),
      Time.now.humanize,
      pkt.ip_saddr,
      pkt.ip_daddr
    ]
  end

  def decrypt_pcap(path)
    pkts = PacketFu::PcapFile.read(path)
    raw = []
    dumps = []

    pkts.each do |pkt|
      next unless pkt.proto.include?(:tcp)

      payload = pkt.payload
      next unless payload.payload_sport == 8281 || payload.payload_dport == 8281
      next unless payload.payload.include?(:raw)

      raw_payload = payload.payload[:raw]

      if raw_payload.length >= 12
        raw.concat(raw_payload.bytes)
        dumps << pkt
      end
    end

    decoded = enc_dec(raw, method(:op_sub), method(:op_add))
    pos = 0
    i = 0

    while pos < raw.length && i < dumps.length
      size = decoded[pos, 2].unpack('v').first
      data = decoded[pos, size]
      dumps[i] = EncDec.dump_pkt(dumps[i], data) + PacketFu::Utils.hexify(data)
      i += 1
      pos += size
    end

    dumps = dumps[0...i]
    [dumps, decoded]
  end
end


options = {}

OptionParser.new do |parser|

  parser.on('-n', '--name NAME', 'Name of the person to greet.') do |n|
    options[:name] = n
  end

  parser.on('-h', '--house HOUSE', 'House of the person.') do |h|
    options[:house] = h
  end
end.parse!

puts "Hello, #{ options[:name] } of house #{ options[:house] }!"
