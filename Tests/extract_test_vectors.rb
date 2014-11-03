#!/usr/bin/env ruby

vectors = []
v = {}

toggle = true
toggle_p_in = false
toggle_p_out = false
toggle_blank = false

File.open("../rfc3610.txt").each do |li|
  if li =~ /^\s*$/


    if toggle && v[:key]
      tl = v[:cipher_length].to_i - v[:length].to_i
      ivl = v[:iv].length/2
      v[:ivl] = ivl
      v[:tl] = tl

      # Save old vector
      # puts "Saving vector " + v[:id]
      vectors.push v
      v = {}
    end
    toggle = false

    next
  elsif li =~ /=============== Packet Vector #(\d+)/
    v = {}
    v[:id] = $1
    toggle = true
    toggle_p_in = false
    toggle_p_out = false
    next
  end

  if toggle
    # a = line.split
    # puts "#{a[1]} #{a[2]}"
    # puts line.split("=",2)[-1].strip

    # New key
    if li =~ /:/
      toggle_p_in = false
      toggle_p_out = false
    end

    if li =~ /AES Key = (.+)/
      v[:key] = $1.gsub(' ', '')
      next
    elsif li =~ /Nonce = (.+)/
      v[:iv] = $1.gsub(' ', '')
      next
    elsif li =~ /Nonce = (.+)/
      v[:iv] = $1.gsub(' ', '')
      next
    elsif li =~ /Total packet length = (\d+)\. \[Input with (\d+) cleartext header octets\]/
      toggle_p_in = true
      v[:lm] = $1
      v[:la] = $2
      v[:data] = ""
      next
    elsif li =~ /Total packet length = (\d+)\. \[Authenticated and Encrypted Output\]/
      toggle_p_out = true
      v[:cipher_length] = $1
      v[:cipher] = ""
      next
    end

    if toggle_p_in
      v[:data] += li.gsub(' ', '').gsub("\n", '')
    end

    if toggle_p_out
      v[:cipher] += li.gsub(' ', '').gsub("\n", '')
    end

  end
end

puts "Extracted " + vectors.count.to_s + " vectors"

require "json"
data = JSON.pretty_generate(vectors)
# puts data

File.open('test_vectors.json', 'w') { |file| file.write(data) }
