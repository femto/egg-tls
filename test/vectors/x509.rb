# Makes the vectors at the end of test/x509.egg: a test PKI of RSA and
# EC roots, intermediates and leaves, and chains to verify, each with
# the answer tls/x509 must give. Every answer is checked with OpenSSL's
# verifier (purpose sslserver, at the case's time, and its host name
# check), except where tls/x509 differs from it by design, which the case
# says.
#
#     ruby test/vectors/x509.rb     # rewrites test/x509.egg after its marker
require "openssl"

T2020 = Time.utc(2020, 1, 1)
T2040 = Time.utc(2040, 1, 1)
NOW = Time.utc(2030, 1, 1).to_i

$serial = 0
def cert(cn, key, issuer: nil, issuer_key: nil, ca: false, pathlen: nil, ku: nil, eku: nil, san: nil,
         nb: T2020, na: T2040, digest: "SHA256", bc: true, extra: [])
  c = OpenSSL::X509::Certificate.new
  c.version = 2
  c.serial = ($serial += 1)
  c.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
  c.issuer = issuer ? issuer.subject : c.subject
  c.public_key = key
  c.not_before = nb
  c.not_after = na
  ef = OpenSSL::X509::ExtensionFactory.new(issuer || c, c)
  if bc
    c.add_extension(ef.create_extension("basicConstraints", "CA:#{ca ? 'TRUE' : 'FALSE'}#{pathlen ? ",pathlen:#{pathlen}" : ''}", true))
  end
  c.add_extension(ef.create_extension("keyUsage", ku, true)) if ku
  c.add_extension(ef.create_extension("extendedKeyUsage", eku, false)) if eku
  c.add_extension(ef.create_extension("subjectAltName", san, false)) if san
  c.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
  extra.each { |e| c.add_extension(e) }
  c.sign(issuer_key || key, OpenSSL::Digest.new(digest))
  c
end

rsa_root_key = OpenSSL::PKey::RSA.new(2048)
ec_root_key = OpenSSL::PKey::EC.generate("secp384r1")
inter_key = OpenSSL::PKey::EC.generate("prime256v1")
inter2_key = OpenSSL::PKey::EC.generate("secp384r1")
leaf_key = OpenSSL::PKey::EC.generate("prime256v1")
rsa_leaf_key = OpenSSL::PKey::RSA.new(2048)
other_key = OpenSSL::PKey::EC.generate("prime256v1")

CA_KU = "keyCertSign,cRLSign"
LEAF_KU = "digitalSignature"
SAN = "DNS:example.com,DNS:*.wild.example,IP:127.0.0.1,IP:::1"

c = {}
c["root_rsa"] = cert("Test RSA Root", rsa_root_key, ca: true, ku: CA_KU)
c["root_ec"] = cert("Test EC Root", ec_root_key, ca: true, ku: CA_KU, digest: "SHA384")
c["inter"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: true, pathlen: 0, ku: CA_KU)
c["inter2"] = cert("Test Inter 2", inter2_key, issuer: c["root_ec"], issuer_key: ec_root_key, ca: true, ku: CA_KU, digest: "SHA384")
c["leaf"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, eku: "serverAuth", san: SAN)
c["leaf_rsa"] = cert("example.com", rsa_leaf_key, issuer: c["inter2"], issuer_key: inter2_key, ku: LEAF_KU, eku: "serverAuth", san: SAN, digest: "SHA384")
c["leaf_sha512"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, san: SAN, digest: "SHA512")
# Variants.
bad = c["leaf"].to_der.bytes
bad[-5] ^= 1
c["leaf_bad_sig"] = OpenSSL::X509::Certificate.new(bad.pack("C*"))
c["leaf_client"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, eku: "clientAuth", san: SAN)
c["leaf_ku_sign"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: "keyCertSign", san: SAN)
c["leaf_critical"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, san: SAN,
                          extra: [OpenSSL::X509::Extension.new("1.3.6.1.4.1.99999.1", OpenSSL::ASN1::Null.new(nil).to_der, true)])
c["leaf_tld_wild"] = cert("example", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, san: "DNS:*.example")
c["leaf_no_san"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU)
c["leaf_no_bc"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, san: SAN, bc: false)
c["self_signed"] = cert("example.com", leaf_key, ku: "digitalSignature,keyCertSign", san: SAN)
c["inter_not_ca"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: false, ku: CA_KU)
c["inter_no_bc"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ku: CA_KU, bc: false)
c["inter_ku"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: true, ku: "digitalSignature")
c["inter_client"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: true, ku: CA_KU, eku: "clientAuth")
c["inter_nc"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: true, ku: CA_KU,
                     extra: [OpenSSL::X509::ExtensionFactory.new(c["root_rsa"]).create_extension("nameConstraints", "permitted;DNS:example.com", true)])
c["inter_expired"] = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: true, ku: CA_KU, na: Time.utc(2025, 1, 1))
c["root_len0"] = cert("Test RSA Root", rsa_root_key, ca: true, pathlen: 0, ku: CA_KU)
c["inter_under_len0"] = cert("Test Inter", inter_key, issuer: c["root_len0"], issuer_key: rsa_root_key, ca: true, ku: CA_KU)
c["inter_b"] = cert("Test Inter B", other_key, issuer: c["inter_under_len0"], issuer_key: inter_key, ca: true, ku: CA_KU)
c["leaf_under_b"] = cert("example.com", leaf_key, issuer: c["inter_b"], issuer_key: other_key, ku: LEAF_KU, san: SAN)
# inter has pathlen 0: a CA under it may not issue.
c["inter_c"] = cert("Test Inter C", other_key, issuer: c["inter"], issuer_key: inter_key, ca: true, ku: CA_KU)
c["leaf_under_c"] = cert("example.com", leaf_key, issuer: c["inter_c"], issuer_key: other_key, ku: LEAF_KU, san: SAN)
# Validity to the second, and past 2049 (GeneralizedTime).
c["leaf_edge"] = cert("example.com", leaf_key, issuer: c["inter"], issuer_key: inter_key, ku: LEAF_KU, san: SAN, na: Time.utc(2030, 1, 1, 0, 0, 0))
c["root_long"] = cert("Test Long Root", ec_root_key, ca: true, ku: CA_KU, na: Time.utc(2060, 1, 1), digest: "SHA384")
c["leaf_long"] = cert("example.com", leaf_key, issuer: c["root_long"], issuer_key: ec_root_key, ku: LEAF_KU, san: SAN,
                      nb: Time.utc(2049, 12, 31, 23, 59, 59), na: Time.utc(2051, 3, 1, 12, 0, 0), digest: "SHA384")
c["other_root"] = cert("Test RSA Root", other_key, ca: true, ku: CA_KU)

# [name, chain, roots, host, now, answer, how OpenSSL compares]
cases = [
  ["EC leaf, EC intermediate, RSA root", %w[leaf inter], %w[root_rsa], "example.com", NOW, "ok"],
  ["RSA leaf, P-384 intermediate and root (SHA-384)", %w[leaf_rsa inter2], %w[root_ec], "example.com", NOW, "ok"],
  ["signed with SHA-512", %w[leaf_sha512 inter], %w[root_rsa], "example.com", NOW, "ok"],
  ["host in another case, and a final dot", %w[leaf inter], %w[root_rsa], "EXAMPLE.Com.", NOW, "ok", "Ruby's host check takes no final dot"],
  ["wildcard", %w[leaf inter], %w[root_rsa], "a.wild.example", NOW, "ok"],
  ["wildcard: two labels", %w[leaf inter], %w[root_rsa], "a.b.wild.example", NOW, "HostMismatch"],
  ["wildcard: no label", %w[leaf inter], %w[root_rsa], "wild.example", NOW, "HostMismatch"],
  ["wildcard: an empty label", %w[leaf inter], %w[root_rsa], ".wild.example", NOW, "HostMismatch"],
  ["wildcard with one label after it", %w[leaf_tld_wild inter], %w[root_rsa], "a.example", NOW, "HostMismatch", "Ruby's host check takes *.example; tls/x509 wants two labels after the *, so *.com cannot match"],
  ["another host", %w[leaf inter], %w[root_rsa], "example.org", NOW, "HostMismatch"],
  ["IPv4", %w[leaf inter], %w[root_rsa], "127.0.0.1", NOW, "ok"],
  ["IPv6", %w[leaf inter], %w[root_rsa], "::1", NOW, "ok"],
  ["IPv6, long form", %w[leaf inter], %w[root_rsa], "0:0:0:0:0:0:0:1", NOW, "ok"],
  ["another IP", %w[leaf inter], %w[root_rsa], "127.0.0.2", NOW, "HostMismatch"],
  ["no subjectAltName (no common name fallback)", %w[leaf_no_san inter], %w[root_rsa], "example.com", NOW, "HostMismatch", "OpenSSL falls back to the common name"],
  ["valid to its last second", %w[leaf_edge inter], %w[root_rsa], "example.com", NOW, "ok", "OpenSSL takes notAfter's own second as expired; RFC 5280 (4.1.2.5) includes it, as Go does"],
  ["expired by a second", %w[leaf_edge inter], %w[root_rsa], "example.com", NOW + 1, "Expired"],
  ["GeneralizedTime, valid", %w[leaf_long], %w[root_long], "example.com", Time.utc(2050, 6, 1).to_i, "ok"],
  ["GeneralizedTime, a second after", %w[leaf_long], %w[root_long], "example.com", Time.utc(2051, 3, 1, 12, 0, 1).to_i, "Expired"],
  ["UTCTime 2049 to GeneralizedTime, a second before", %w[leaf_long], %w[root_long], "example.com", Time.utc(2049, 12, 31, 23, 59, 58).to_i, "NotYetValid"],
  ["expired", %w[leaf inter], %w[root_rsa], "example.com", Time.utc(2041, 1, 1).to_i, "Expired"],
  ["not yet valid", %w[leaf inter], %w[root_rsa], "example.com", Time.utc(2019, 1, 1).to_i, "NotYetValid"],
  ["intermediate expired", %w[leaf inter_expired], %w[root_rsa], "example.com", NOW, "Expired"],
  ["no intermediate", %w[leaf], %w[root_rsa], "example.com", NOW, "UnknownIssuer"],
  ["untrusted root", %w[leaf inter], %w[root_ec], "example.com", NOW, "UnknownIssuer"],
  ["root of the same name, another key", %w[leaf inter], %w[other_root], "example.com", NOW, "BadSignature"],
  ["out of order", %w[leaf inter2 inter], %w[root_rsa], "example.com", NOW, "UnknownIssuer", "OpenSSL builds its own path"],
  ["leaf signature changed", %w[leaf_bad_sig inter], %w[root_rsa], "example.com", NOW, "BadSignature"],
  ["intermediate not a CA", %w[leaf inter_not_ca], %w[root_rsa], "example.com", NOW, "NotCA"],
  ["intermediate without basicConstraints", %w[leaf inter_no_bc], %w[root_rsa], "example.com", NOW, "NotCA"],
  ["intermediate without keyCertSign", %w[leaf inter_ku], %w[root_rsa], "example.com", NOW, "BadKeyUsage"],
  ["intermediate for clients only", %w[leaf inter_client], %w[root_rsa], "example.com", NOW, "BadExtKeyUsage"],
  ["intermediate with critical nameConstraints", %w[leaf inter_nc], %w[root_rsa], "example.com", NOW, "UnknownCriticalExtension", "OpenSSL supports nameConstraints"],
  ["leaf for clients only", %w[leaf_client inter], %w[root_rsa], "example.com", NOW, "BadExtKeyUsage"],
  ["leaf without digitalSignature", %w[leaf_ku_sign inter], %w[root_rsa], "example.com", NOW, "BadKeyUsage"],
  ["leaf with an unknown critical extension", %w[leaf_critical inter], %w[root_rsa], "example.com", NOW, "UnknownCriticalExtension"],
  ["leaf without basicConstraints", %w[leaf_no_bc inter], %w[root_rsa], "example.com", NOW, "ok"],
  ["pathLenConstraint 0 on the root, two intermediates", %w[leaf_under_b inter_b inter_under_len0], %w[root_len0], "example.com", NOW, "PathLenExceeded"],
  ["pathLenConstraint 0 on the intermediate, a CA under it", %w[leaf_under_c inter_c inter], %w[root_rsa], "example.com", NOW, "PathLenExceeded"],
  ["a self-signed leaf trusted as a root", %w[self_signed], %w[self_signed], "example.com", NOW, "ok"],
  ["a self-signed leaf not trusted", %w[self_signed], %w[root_rsa], "example.com", NOW, "UnknownIssuer"],
  ["the root sent too", %w[leaf inter root_rsa], %w[root_rsa], "example.com", NOW, "ok"],
  ["eleven certificates", %w[leaf inter] * 5 + %w[leaf], %w[root_rsa], "example.com", NOW, "ChainTooLong", "OpenSSL has no such limit"],
]

cases.each do |name, chain, roots, host, now, want, differs|
  next if differs
  store = OpenSSL::X509::Store.new
  roots.each { |r| store.add_cert(c.fetch(r)) }
  store.purpose = OpenSSL::X509::PURPOSE_SSL_SERVER
  store.time = Time.at(now)
  ctx = OpenSSL::X509::StoreContext.new(store, c.fetch(chain[0]), chain[1..].map { |x| c.fetch(x) })
  ok = ctx.verify && OpenSSL::SSL.verify_certificate_identity(c.fetch(chain[0]), host)
  abort "OpenSSL says #{ok} (#{ctx.error_string}) for #{name}" unless ok == (want == "ok")
end

lit = ->(x) { "\"#{x}\"" }
out = +"// The test PKI: name, DER.\nfn certs() [#{c.size}]Named {\n    return [#{c.size}]Named{\n"
c.each { |n, x| out << "        Named{ .name = #{lit.(n)}, .der = #{lit.(x.to_der.unpack1('H*'))} },\n" }
out << "    }\n}\n\n// Chains: name, certificates (leaf first), roots, host, time, answer.\n"
out << "fn cases() [#{cases.size}]Case {\n    return [#{cases.size}]Case{\n"
cases.each do |name, chain, roots, host, now, want, differs|
  label = differs ? "#{name} (unlike OpenSSL: #{differs})" : name
  out << "        Case{ .name = #{lit.(label)}, .chain = #{lit.(chain.join(','))}, .roots = #{lit.(roots.join(','))}, .host = #{lit.(host)}, .now = #{now}, .want = #{lit.(want)} },\n"
end
out << "    }\n}\n"

# PEM: the two roots, with a block between them that is base64 but no
# certificate, and text around them, as bundles have.
pem = +"Bundle\n"
pem << c["root_rsa"].to_pem
pem << "-----BEGIN CERTIFICATE-----\nAAECAwQF\n-----END CERTIFICATE-----\n"
pem << "# a comment\n" << c["root_ec"].to_pem
out << "\n// Two roots in PEM, and a block that is no certificate.\nconst PEM = #{pem.inspect}\n"
abort "PEM has a quote" if pem.include?('"')

path = File.expand_path("../x509.egg", __dir__)
marker = "// Made by test/vectors/x509.rb; do not edit below.\n"
src = File.exist?(path) ? File.read(path) : ""
head = src.include?(marker) ? src[0...src.index(marker)] : src
File.write(path, head + marker + out)
puts "#{c.size} certificates, #{cases.size} cases"
