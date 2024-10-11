#!/usr/bin/env ruby
def read_keys(path)
  begin
    keys = File.open(path, "rb:ASCII-8BIT", &:read)
  rescue => error
    puts "Failed to open keys file", error
    return false, ""
  end
  return true, keys
end

def read_data_file(path)
  begin
    buffer = File.open(path, "rb:ASCII-8BIT", &:read)
  rescue => error
    puts "Failed to open data file", error
    return false, "", 0
  end
  return true, buffer, buffer.size
end

def encrypt(decrypted_file_raw, length, keys)
  off = 0
  while off < length do
    packet_length = decrypted_file_raw[off, 2].unpack("S").first
    key = decrypted_file_raw[off + 2].unpack("C").first
    key = keys[(key << 1) % 512].unpack("C").first
    (off + 4...off + packet_length).each do |i|
      mapped_key = keys[((key % 256) << 1) % 512 + 1].unpack("C").first
      curr_value = decrypted_file_raw[i].unpack("C").first
      case i & 3
      when 0
        curr_value = (curr_value + (mapped_key << 1)) & 255
      when 1
        curr_value = (curr_value - (mapped_key >> 3)) & 255
      when 2
        curr_value = (curr_value + (mapped_key << 2)) & 255
      when 3
        curr_value = (curr_value - (mapped_key >> 5)) & 255
      end
      decrypted_file_raw[i] = [curr_value].pack("C")
      key += 1
    end
    off += packet_length
  end
end

def decrypt(encrypted_file_raw, length, keys)
  off = 0
  while off < length do
    packet_length = encrypted_file_raw[off, 2].unpack("S").first
    key = encrypted_file_raw[off + 2].unpack("C").first
    key = keys[key << 1].unpack("C").first
    (off + 4...off + packet_length).each do |i|
      mapped_key = keys[((key % 256) << 1) % 512 + 1].unpack("C").first
      curr_value = encrypted_file_raw[i].unpack("C").first
      case i & 3
      when 0
        curr_value = (curr_value - (mapped_key << 1)) & 255
      when 1
        curr_value = (curr_value + (mapped_key >> 3)) & 255
      when 2
        curr_value = (curr_value - (mapped_key << 2)) & 255
      when 3
        curr_value = (curr_value + (mapped_key >> 5)) & 255
      end
      encrypted_file_raw[i] = [curr_value].pack("C")
      key += 1
    end
    off += packet_length
  end
end

if ARGV.length < 4
  exit(-1)
end

success, keys = read_keys(ARGV[0])
exit(-2) unless success

success, encrypted_file_raw, encrypted_file_raw_size = read_data_file(ARGV[2])
exit(-3) unless success

success, decrypted_file_raw, decrypted_file_raw_size = read_data_file(ARGV[3])
exit(-4) unless success

op = ARGV[1]
if op == "enc"
  encrypt(decrypted_file_raw, decrypted_file_raw_size, keys)
  File.open("./encoded.bin", "wb") { |file| file.write(decrypted_file_raw) }
elsif op == "dec"
  decrypt(encrypted_file_raw, encrypted_file_raw_size, keys)
  File.open("./decoded.bin", "wb") { |file| file.write(encrypted_file_raw) }
end

diff = 0
(0...encrypted_file_raw_size).each do |i|
  diff += 1 if encrypted_file_raw[i] != decrypted_file_raw[i]
end

puts "#{diff} differences"
