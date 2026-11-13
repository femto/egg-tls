# Makes the vectors at the end of test/rsa.egg: OpenSSL's keys and
# signatures, and encodings built by hand and signed with the raw private
# operation. Every expected answer is checked with OpenSSL first.
#
#     ruby test/vectors/rsa.rb     # rewrites test/rsa.egg after its marker
require "openssl"

H = { "sha256" => 32, "sha384" => 48, "sha512" => 64 }
PREFIX = {
  "sha256" => "3031300d060960864801650304020105000420",
  "sha384" => "3041300d060960864801650304020205000430",
  "sha512" => "3051300d060960864801650304020305000440",
}
hx = ->(s) { s.unpack1("H*") }

# A key from two primes, so its modulus has exactly bits bits (OpenSSL
# rounds an odd size down).
def key_of_bits(bits, e = 65537)
  loop do
    p = OpenSSL::BN.generate_prime((bits + 1) / 2)
    q = OpenSSL::BN.generate_prime(bits / 2)
    n = p * q
    next unless n.num_bits == bits
    phi = (p - 1) * (q - 1)
    next unless phi.gcd(e) == 1
    d = OpenSSL::BN.new(e).mod_inverse(phi)
    seq = [0, n, e, d, p, q, d % (p - 1), d % (q - 1), q.mod_inverse(p)].map { |x| OpenSSL::ASN1::Integer(OpenSSL::BN.new(x)) }
    return OpenSSL::PKey.read(OpenSSL::ASN1::Sequence(seq).to_der)
  end
end

keys = {
  "k2048" => OpenSSL::PKey::RSA.new(2048),
  "k2049" => key_of_bits(2049),
  "k3072" => OpenSSL::PKey::RSA.new(3072),
  "k4096" => OpenSSL::PKey::RSA.new(4096),
  "k2048e3" => OpenSSL::PKey::RSA.new(2048, 3),
  "k8192" => OpenSSL::PKey::RSA.new(8192),
  "k1024" => OpenSSL::PKey::RSA.new(1024),
}
{ "k2048" => 2048, "k2049" => 2049, "k3072" => 3072, "k4096" => 4096, "k2048e3" => 2048, "k8192" => 8192, "k1024" => 1024 }.each do |kn, bits|
  abort "#{kn} has #{keys[kn].n.num_bits} bits" unless keys[kn].n.num_bits == bits
end

v = []
msg = "egg-tls rsa"
check = lambda do |k, kind, h, dg, sig, salt|
  pub = OpenSSL::PKey.read(k.public_to_der)
  opts = kind == "pss" ? { rsa_padding_mode: "pss", rsa_pss_saltlen: salt, rsa_mgf1_md: h } : {}
  pub.verify_raw(h, sig, dg, opts)
rescue OpenSSL::PKey::PKeyError
  false
end
add = lambda do |kn, kind, h, dg, sig, salt, ok, name|
  got = check.(keys[kn], kind, h, dg, sig, salt)
  abort "OpenSSL says #{got} for #{name}" unless got == ok
  v << [kn, kind, h, hx.(dg), hx.(sig), salt, ok, name]
end

%w[k2048 k2049 k3072 k4096 k2048e3 k8192].each do |kn|
  k = keys[kn]
  H.each do |h, hl|
    dg = OpenSSL::Digest.digest(h, msg)
    add.(kn, "pkcs1", h, dg, k.sign_raw(h, dg), 0, true, "#{kn} PKCS#1 v1.5 #{h}")
    add.(kn, "pss", h, dg, k.sign_raw(h, dg, rsa_padding_mode: "pss", rsa_pss_saltlen: hl, rsa_mgf1_md: h), hl, true, "#{kn} PSS #{h}")
  end
end

k = keys["k2048"]
dg = OpenSSL::Digest.digest("sha256", msg)
good = k.sign_raw("sha256", dg)
pss = k.sign_raw("sha256", dg, rsa_padding_mode: "pss", rsa_pss_saltlen: 32, rsa_mgf1_md: "sha256")
flip = ->(s, i) { b = s.bytes; b[i] ^= 1; b.pack("C*") }
add.("k2048", "pss", "sha256", dg, k.sign_raw("sha256", dg, rsa_padding_mode: "pss", rsa_pss_saltlen: 0, rsa_mgf1_md: "sha256"), 0, true, "PSS with no salt")
add.("k2048", "pss", "sha256", dg, k.sign_raw("sha256", dg, rsa_padding_mode: "pss", rsa_pss_saltlen: 20, rsa_mgf1_md: "sha256"), 20, true, "PSS with a 20-byte salt")
add.("k2048", "pkcs1", "sha256", dg, flip.(good, 100), 0, false, "PKCS#1: a signature byte changed")
add.("k2048", "pkcs1", "sha256", flip.(dg, 0), good, 0, false, "PKCS#1: the digest changed")
add.("k2048", "pss", "sha256", dg, flip.(pss, 100), 32, false, "PSS: a signature byte changed")
add.("k2048", "pss", "sha256", flip.(dg, 0), pss, 32, false, "PSS: the digest changed")
add.("k2048", "pss", "sha256", dg, pss, 20, false, "PSS: another salt length")
add.("k2048", "pkcs1", "sha256", dg, pss, 0, false, "a PSS signature as PKCS#1")
add.("k2048", "pss", "sha256", dg, good, 32, false, "a PKCS#1 signature as PSS")
add.("k2048", "pkcs1", "sha256", dg, "\x00" + good, 0, false, "PKCS#1: a zero byte in front")
add.("k2048", "pkcs1", "sha256", dg, good[1..], 0, false, "PKCS#1: a byte short")
add.("k2048", "pkcs1", "sha256", dg, [k.n.to_s(16).rjust(512, "0")].pack("H*"), 0, false, "PKCS#1: the signature is n")
add.("k3072", "pkcs1", "sha256", dg, good, 0, false, "another key")

size = 256
raw = ->(em_hex) { k.sign_raw(nil, [em_hex].pack("H*"), rsa_padding_mode: "none") }
t = PREFIX["sha256"] + hx.(dg)
pad = ->(tail, type = "01") { "00" + type + "ff" * (size - 3 - tail.size / 2) + "00" + tail }
add.("k2048", "pkcs1", "sha256", dg, raw.(pad.(t)), 0, true, "PKCS#1 built by hand")
add.("k2048", "pkcs1", "sha256", dg, raw.(pad.("302f300b0609608648016503040201" + "0420" + hx.(dg))), 0, false, "PKCS#1: DigestInfo without NULL")
garbage = "00" + "01" + "ff" * 8 + "00" + t + "aa" * (size - 11 - t.size / 2)
add.("k2048", "pkcs1", "sha256", dg, raw.(garbage), 0, false, "PKCS#1: short padding, garbage after the digest")
add.("k2048", "pkcs1", "sha256", dg, raw.(pad.(t, "02")), 0, false, "PKCS#1: block type 2")
fe = pad.(t); fe = fe[0, 20] + "fe" + fe[22..]
add.("k2048", "pkcs1", "sha256", dg, raw.(fe), 0, false, "PKCS#1: an FE in the padding")
em = hx.(OpenSSL::PKey.read(k.public_to_der).verify_recover(nil, pss, rsa_padding_mode: "none"))
add.("k2048", "pss", "sha256", dg, raw.(em[0..-3] + "bb"), 32, false, "PSS: trailer 0xbb")
# With the top bit set, EM must still be below n to be signed raw.
top = nil
loop do
  e2 = hx.(OpenSSL::PKey.read(k.public_to_der).verify_recover(nil, k.sign_raw("sha256", dg, rsa_padding_mode: "pss", rsa_pss_saltlen: 32, rsa_mgf1_md: "sha256"), rsa_padding_mode: "none"))
  top = format("%02x", e2[0, 2].to_i(16) | 0x80) + e2[2..]
  break if top.to_i(16) < k.n.to_i
end
add.("k2048", "pss", "sha256", dg, raw.(top), 32, false, "PSS: the top bit set")
add.("k2048", "pss", "sha256", dg, raw.(em), 32, true, "PSS re-signed raw")

# 2049 bits: PSS's EM is one byte shorter than the modulus, and the
# modulus's first byte is 0x01.
k9 = keys["k2049"]
# A good EM with 0x01 in front is still below n when EM is below n's last
# 256 bytes; PSS salts are random, so sign until one is.
n_rest = k9.n.to_s(16).rjust(514, "0")[2..].to_i(16)
m9 = nil
loop do
  pss9 = k9.sign_raw("sha256", dg, rsa_padding_mode: "pss", rsa_pss_saltlen: 32, rsa_mgf1_md: "sha256")
  m9 = hx.(OpenSSL::PKey.read(k9.public_to_der).verify_recover(nil, pss9, rsa_padding_mode: "none"))
  abort "2049: first byte #{m9[0, 2]}" unless m9.size == 2 * 257 && m9[0, 2] == "00"
  break if m9[2..].to_i(16) < n_rest
end
raw9 = ->(h) { k9.sign_raw(nil, [h].pack("H*"), rsa_padding_mode: "none") }
add.("k2049", "pss", "sha256", dg, raw9.(m9), 32, true, "2049 bits, PSS re-signed raw")
add.("k2049", "pss", "sha256", dg, raw9.("01" + m9[2..]), 32, false, "2049 bits, PSS: the byte before EM not zero")

hexs = ->(x) { s = x.to_s(16).downcase; s.size.odd? ? "0" + s : s }
lit = ->(x) { "\"#{x}\"" }
out = +"// Keys made by OpenSSL: name, modulus, exponent.\nfn keys() [#{keys.size}]Key {\n    return [#{keys.size}]Key{\n"
keys.each { |kn, kk| out << "        Key{ .name = #{lit.(kn)}, .n = #{lit.(hexs.(kk.n))}, .e = #{lit.(hexs.(kk.e))} },\n" }
out << "    }\n}\n\n// Signatures: key, scheme, hash, digest, signature, salt length,\n// verifies, name. OpenSSL agreed with each expected answer.\n"
out << "fn sigs() [#{v.size}]Sig {\n    return [#{v.size}]Sig{\n"
v.each { |kn, kind, h, d, s, salt, ok, nm| out << "        Sig{ .key = #{lit.(kn)}, .kind = #{lit.(kind)}, .hash = #{lit.(h)}, .digest = #{lit.(d)}, .sig = #{lit.(s)}, .salt = #{salt}, .ok = #{ok}, .name = #{lit.(nm)} },\n" }
out << "    }\n}\n"

path = File.expand_path("../rsa.egg", __dir__)
marker = "// Made by test/vectors/rsa.rb; do not edit below.\n"
src = File.read(path)
head = src.include?(marker) ? src[0...src.index(marker)] : src[0...src.index("// Keys made by OpenSSL")]
File.write(path, head + marker + out)
puts "#{v.size} signatures, #{keys.size} keys"
