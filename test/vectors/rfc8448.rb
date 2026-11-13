# Makes the vectors at the end of test/hrr.egg, from RFC 8448 (downloaded,
# or the path given) section 5, a handshake with a HelloRetryRequest; the
# ClientHellos tls/client builds itself, from RFC 8446 by hand; and
# HelloRetryRequests and ServerHellos it must refuse. Also rewrites
# REC_OUR_CH in test/rfc8448.egg.
#
#     ruby test/vectors/rfc8448.rb [rfc8448.txt]
require "openssl"
require "open-uri"

text = ARGV[0] ? File.read(ARGV[0]) : URI.open("https://www.rfc-editor.org/rfc/rfc8448.txt").read
lines = text.split("\n").reject { |l| l =~ /^RFC 8448|^Thomson|^\f/ || l.strip.empty? }
from = lines.index { |l| l.start_with?("5.  HelloRetryRequest") }
to = lines.index { |l| l.start_with?("6.  Client Authentication") }
steps = []
lines[from...to].each do |l|
  if l =~ /^   \{(\w+)\}\s+(.*)/
    steps << ["#{$1}: #{$2}", []]
  elsif steps.any?
    steps.last[1] << l
  end
end
rows = []
steps.each do |head, body|
  fields = []
  body.each do |l|
    if l =~ /^      ([\w ]+?) \((\d+) octets\):\s*(.*)$/
      fields << [$1, $2.to_i, $3.split.join]
    elsif fields.any? && l =~ /^         ((?:[0-9a-f]{2}\s*)+)$/
      fields.last[2] << $1.split.join
    end
  end
  fields.each do |n, len, hex|
    next if hex.start_with?("(")
    abort "#{head} #{n}: #{hex.size / 2} bytes, not #{len}" unless hex.size == 2 * len || hex == ""
    rows << [head, n, hex]
  end
end
find = lambda do |head, name, nth = 0|
  r = rows.select { |h, n, _| h.start_with?(head) && n == name }[nth]
  abort "missing #{head} / #{name} / #{nth}" unless r
  r[2]
end

v = {}
v[:x_priv] = find.("client: create an ephemeral x25519", "private key")
v[:p_priv] = find.("client: create an ephemeral P-256", "private key")
v[:p_pub] = find.("client: create an ephemeral P-256", "public key")
v[:ch1] = find.("client: construct a ClientHello", "ClientHello", 0)
v[:rec_ch1] = find.("client: send handshake record", "complete record", 0)
v[:hrr] = find.("server: construct a ServerHello", "ServerHello", 0)
v[:rec_hrr] = find.("server: send handshake record", "complete record", 0)
v[:ch2] = find.("client: construct a ClientHello", "ClientHello", 1)
v[:rec_ch2] = find.("client: send handshake record", "complete record", 1)
v[:rec_sh] = find.("server: send handshake record", "complete record", 1)
v[:rec_flight] = find.("server: send handshake record", "complete record", 2)
v[:rec_cfin] = find.("client: send handshake record", "complete record", 2)
v[:rec_calert] = find.("client: send alert record", "complete record")
v[:rec_salert] = find.("server: send alert record", "complete record")
abort "HRR random" unless v[:hrr][12, 64] == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
abort "record" unless v[:rec_ch2] == "1603030200" + v[:ch2]
g = OpenSSL::PKey::EC::Group.new("prime256v1")
abort "P-256 key" unless g.generator.mul(OpenSSL::BN.new(v[:p_priv], 16)).to_octet_string(:uncompressed).unpack1("H*") == v[:p_pub]

def u16(x) = format("%04x", x)
def u24(x) = format("%06x", x)
def record(type, version, body) = type + version + u16(body.size / 2) + body
def ext(type, data) = u16(type) + u16(data.size / 2) + data

# A HelloRetryRequest with these extensions (hex), for suite 0x1301.
MAGIC = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
def hrr(exts, suite = "1301")
  body = "0303" + MAGIC + "00" + suite + "00" + u16(exts.size / 2) + exts
  record("16", "0303", "02" + u24(body.size / 2) + body)
end
VERSIONS = ext(43, "0304")

# tls/client's ClientHello for example.com, random 00..1f: X25519 share of
# RFC 8448 section 3's client key, P-256 of RFC 6979's, P-384 of 7.
X_PRIV3 = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
X_PUB3 = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
P256_PRIV = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
p256_pub = g.generator.mul(OpenSSL::BN.new(P256_PRIV, 16)).to_octet_string(:uncompressed).unpack1("H*")
p384_pub = OpenSSL::PKey::EC::Group.new("secp384r1").generator.mul(OpenSSL::BN.new("7", 16)).to_octet_string(:uncompressed).unpack1("H*")
def our_hello(shares, cookie = "")
  host = "example.com".unpack1("H*")
  sni = ext(0, u16(host.size / 2 + 3) + "00" + u16(host.size / 2) + host)
  groups = ext(10, u16(6) + "001d00170018")
  schemes = %w[0403 0503 0804 0805 0806 0401 0501 0601].join
  sigs = ext(13, u16(schemes.size / 2) + schemes)
  vers = ext(43, "020304")
  cook = cookie.empty? ? "" : ext(44, u16(cookie.size / 2) + cookie)
  list = shares.map { |grp, pub| u16(grp) + u16(pub.size / 2) + pub }.join
  share = ext(51, u16(list.size / 2) + list)
  exts = sni + groups + sigs + vers + cook + share
  rnd = (0..31).map { |i| format("%02x", i) }.join
  body = "0303" + rnd + "00" + u16(6) + "130313011302" + "0100" + u16(exts.size / 2) + exts
  "01" + u24(body.size / 2) + body
end
v[:x_priv3] = X_PRIV3
v[:p256_priv] = P256_PRIV
v[:rec_our_ch] = record("16", "0301", our_hello([[0x1d, X_PUB3], [0x17, p256_pub]]))
cookie = "636f6f6b6965"
v[:hrr_p384] = hrr(VERSIONS + ext(51, "0018") + ext(44, u16(3) + cookie[0, 6]))
v[:rec_our_ch2] = record("16", "0303", our_hello([[0x18, p384_pub]], cookie[0, 6]))
v[:hrr_cookie_only] = hrr(VERSIONS + ext(44, u16(6) + cookie))
v[:rec_our_ch2_cookie] = record("16", "0303", our_hello([[0x1d, X_PUB3], [0x17, p256_pub]], cookie))
# Must be refused.
v[:hrr_offered] = hrr(VERSIONS + ext(51, "001d"))
v[:hrr_unknown_group] = hrr(VERSIONS + ext(51, "0019"))
v[:hrr_group0_cookie] = hrr(VERSIONS + ext(51, "0000") + ext(44, u16(6) + cookie))
v[:hrr_no_change] = hrr(VERSIONS)
v[:hrr_no_version] = hrr(ext(51, "0018"))
v[:hrr_bad_suite] = hrr(VERSIONS + ext(51, "0018"), "1304")
v[:hrr_unknown_ext] = hrr(VERSIONS + ext(51, "0018") + ext(0x0f, "01"))
# The RFC's ServerHello after its HelloRetryRequest, changed: another suite
# (0x1302), or an X25519 share the second ClientHello did not carry.
sh = v[:rec_sh][10..]
abort "suite" unless sh[8 + 4 + 64 + 2, 4] == "1301"
v[:rec_sh_other_suite] = "16" + "0303" + v[:rec_sh][6, 4] + sh.sub(/\A(.{#{8 + 4 + 64 + 2}})1301/, "\\11302")
x_share = ext(51, "001d0020" + "11" * 32)
sh_body = "0303" + sh[12, 64] + "00" + "1301" + "00" + u16((VERSIONS + x_share).size / 2) + VERSIONS + x_share
v[:rec_sh_x25519] = record("16", "0303", "02" + u24(sh_body.size / 2) + sh_body)

out = +"\n"
v.each { |k, x| out << "const #{k.to_s.upcase} = \"#{x}\"\n" }
path = File.expand_path("../hrr.egg", __dir__)
marker = "// Made by test/vectors/rfc8448.rb; do not edit below.\n"
src = File.exist?(path) ? File.read(path) : ""
head = src.include?(marker) ? src[0...src.index(marker)] : src
File.write(path, head + marker + out)
r8448 = File.expand_path("../rfc8448.egg", __dir__)
s = File.read(r8448)
s = s.sub(/^const REC_OUR_CH = "[0-9a-f]+"$/) { "const REC_OUR_CH = \"#{v[:rec_our_ch]}\"" }
File.write(r8448, s)
puts "#{v.size} vectors"
