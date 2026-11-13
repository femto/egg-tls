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

# Certificates made wrong on purpose: a leaf's TBSCertificate taken
# apart into the DER of its fields, changed, and signed again by inter.
def tlv(tag, content)
  n = content.bytesize
  len = n < 0x80 ? [n].pack("C") : (n < 0x100 ? [0x81, n].pack("C*") : [0x82, n >> 8, n & 0xFF].pack("C*"))
  [tag].pack("C") + len + content
end

def ext(oid, value, critical: false)
  tlv(0x30, OpenSSL::ASN1::ObjectId(oid).to_der + (critical ? "\x01\x01\xff".b : "".b) + tlv(0x04, value))
end

def forge(base, key)
  tbs = OpenSSL::ASN1.decode(base.to_der).value[0]
  parts = tbs.value.map { |x| x.to_der }
  exts = OpenSSL::ASN1.decode(parts[7]).value[0].value.map { |x| x.to_der }
  yield parts, exts
  parts[7] = tlv(0xA3, tlv(0x30, exts.join)) if parts[7] && parts[7].getbyte(0) == 0xA3 && !parts[7].frozen?
  tbs_der = tlv(0x30, parts.compact.join)
  alg = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("ecdsa-with-SHA256")]).to_der
  sig = key.sign("SHA256", tbs_der)
  tlv(0x30, tbs_der + alg + tlv(0x03, "\x00".b + sig))
end

# RSA-PSS signatures (RFC 4055): a certificate's signature algorithm, inner
# and outer, replaced by id-RSASSA-PSS with params, and the TBSCertificate
# signed again by the issuer's RSA key with PSS (md, MGF1 over mgf, salt).
OID_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
HASH_OID = { "SHA1" => "1.3.14.3.2.26", "SHA256" => "2.16.840.1.101.3.4.2.1",
             "SHA384" => "2.16.840.1.101.3.4.2.2", "SHA512" => "2.16.840.1.101.3.4.2.3" }
def hash_id(md, null: true) = tlv(0x30, OpenSSL::ASN1::ObjectId(HASH_OID[md]).to_der + (null ? "\x05\x00".b : "".b))
def pss_params(md, mgf: md, salt:, null: true, extra: "".b)
  tlv(0x30, tlv(0xA0, hash_id(md, null: null)) +
            tlv(0xA1, tlv(0x30, OpenSSL::ASN1::ObjectId(OID_MGF1).to_der + hash_id(mgf, null: null))) +
            tlv(0xA2, OpenSSL::ASN1::Integer(salt).to_der) + extra)
end
def pss_sign(base, key, params, md, mgf: md, salt:)
  parts = OpenSSL::ASN1.decode(base.to_der).value[0].value.map { |x| x.to_der }
  alg = tlv(0x30, OpenSSL::ASN1::ObjectId(OID_PSS).to_der + params)
  parts[2] = alg
  tbs_der = tlv(0x30, parts.join)
  sig = key.sign(md, tbs_der, rsa_padding_mode: "pss", rsa_pss_saltlen: salt, rsa_mgf1_md: mgf)
  tlv(0x30, tbs_der + alg + tlv(0x03, "\x00".b + sig))
end
pss_base = cert("example.com", leaf_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ku: LEAF_KU, eku: "serverAuth", san: SAN)
pss = {}
pss["pss_sha256"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA256", salt: 32), "SHA256", salt: 32)
pss["pss_sha384"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA384", salt: 48), "SHA384", salt: 48)
pss["pss_sha512"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA512", salt: 64), "SHA512", salt: 64)
pss["pss_no_null"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA256", salt: 32, null: false), "SHA256", salt: 32)
pss["pss_salt20"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA256", salt: 20), "SHA256", salt: 20)
pss["pss_mgf_sha1"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA256", mgf: "SHA1", salt: 32), "SHA256", mgf: "SHA1", salt: 32)
pss["pss_defaults"] = pss_sign(pss_base, rsa_root_key, "".b, "SHA1", salt: 20)
pss["pss_trailer2"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA256", salt: 32, extra: tlv(0xA3, "\x02\x01\x02".b)), "SHA256", salt: 32)
pss["pss_junk"] = pss_sign(pss_base, rsa_root_key, pss_params("SHA256", salt: 32, extra: "\x05\x00".b), "SHA256", salt: 32)
bad_pss = pss["pss_sha256"].bytes
bad_pss[-7] ^= 1
pss["pss_bad_sig"] = bad_pss.pack("C*")
# An intermediate signed with PSS, over a leaf signed with ECDSA.
inter_pss_base = cert("Test Inter", inter_key, issuer: c["root_rsa"], issuer_key: rsa_root_key, ca: true, pathlen: 0, ku: CA_KU)
pss["inter_pss"] = pss_sign(inter_pss_base, rsa_root_key, pss_params("SHA384", salt: 48), "SHA384", salt: 48)

SAN_DER = OpenSSL::X509::ExtensionFactory.new.create_extension("subjectAltName", SAN).to_der
bad = {}
bad["bad_tag0"] = forge(c["leaf"], inter_key) { |_, e| e.map! { |x| x == SAN_DER ? ext("subjectAltName", tlv(0x30, "\x00\x00".b + tlv(0x82, "example.com"))) : x } }
bad["bad_gentime"] = forge(c["leaf"], inter_key) { |p, _| p[4] = tlv(0x30, tlv(0x17, "200101000000Z") + tlv(0x18, "20350101000000Z")) }
bad["bad_version0"] = forge(c["leaf_no_bc"], inter_key) { |p, _| p[0] = tlv(0xA0, "\x02\x01\x00".b) }
bad["bad_version3"] = forge(c["leaf"], inter_key) { |p, _| p[0] = tlv(0xA0, "\x02\x01\x03".b) }
bad["bad_version_extra"] = forge(c["leaf"], inter_key) { |p, _| p[0] = tlv(0xA0, "\x02\x01\x02\x05\x00".b) }
bad["bad_serial_negative"] = forge(c["leaf"], inter_key) { |p, _| p[1] = "\x02\x01\xfb".b }
bad["bad_serial_long_form"] = forge(c["leaf"], inter_key) { |p, _| p[1] = "\x02\x02\x00\x05".b }
bad["bad_pathlen_leaf"] = forge(c["leaf"], inter_key) { |_, e| e[0] = ext("basicConstraints", tlv(0x30, "\x02\x01\x01".b), critical: true) }
bad["bad_duplicate_san"] = forge(c["leaf"], inter_key) { |_, e| e << ext("subjectAltName", tlv(0x30, tlv(0x82, "evil.example"))) }
bad["bad_ku_unused_bits"] = forge(c["leaf"], inter_key) { |_, e| e[1] = ext("keyUsage", "\x03\x02\x07\x81".b, critical: true) }
bad["bad_ku_too_long"] = forge(c["leaf"], inter_key) { |_, e| e[1] = ext("keyUsage", "\x03\x04\x00\x80\x00\x01".b, critical: true) }
bad["bad_oid"] = forge(c["leaf"], inter_key) { |_, e| e << tlv(0x30, "\x06\x03\x80\x01\x02".b + tlv(0x04, "\x05\x00".b)) }
bad["bad_policies"] = forge(c["leaf"], inter_key) { |_, e| e << ext("certificatePolicies", tlv(0x30, tlv(0x30, "\x02\x01\x01".b))) }
bad["bad_ext_wrapper"] = forge(c["leaf"], inter_key) { |p, e| p[7] = tlv(0xA3, tlv(0x30, e.join) + "\x05\x00".b).freeze }
pol = ->(oid, quals = nil) { tlv(0x30, OpenSSL::ASN1::ObjectId(oid).to_der + (quals ? tlv(0x30, quals) : "".b)) }
cps = tlv(0x30, OpenSSL::ASN1::ObjectId("1.3.6.1.5.5.7.2.1").to_der + tlv(0x16, "https://example.com/cps"))
bad["bad_many_extensions"] = forge(c["leaf"], inter_key) { |_, e| 60.times { |i| e << ext("1.3.6.1.4.1.99999.2.#{i}", "\x05\x00".b) } }
bad["bad_policy_twice"] = forge(c["leaf"], inter_key) { |_, e| e << ext("certificatePolicies", tlv(0x30, pol.("2.23.140.1.2.1") + pol.("2.23.140.1.2.1"))) }
bad["bad_policy_qualifier"] = forge(c["leaf"], inter_key) { |_, e| e << ext("certificatePolicies", tlv(0x30, pol.("2.23.140.1.2.1", tlv(0x30, "\x02\x01\x01".b)))) }
bad["bad_policy_no_qualifiers"] = forge(c["leaf"], inter_key) { |_, e| e << ext("certificatePolicies", tlv(0x30, pol.("2.23.140.1.2.1", "".b))) }
ok_policies = forge(c["leaf"], inter_key) { |_, e| e << ext("certificatePolicies", tlv(0x30, pol.("2.23.140.1.2.1") + pol.("1.3.6.1.4.1.44947.1.1.1", cps))) }

# The Trustwave ECC roots' keyUsage: unused bits zero, but a trailing
# zero byte DER would drop. Taken.
ok_ku = forge(c["leaf"], inter_key) { |_, e| e[1] = ext("keyUsage", "\x03\x03\x07\x80\x00".b, critical: true) }

# [name, chain, roots, host, now, answer, how OpenSSL compares]
cases = [
  ["RSA-PSS, SHA-256", %w[pss_sha256], %w[root_rsa], "example.com", NOW, "ok"],
  ["RSA-PSS, SHA-384", %w[pss_sha384], %w[root_rsa], "example.com", NOW, "ok"],
  ["RSA-PSS, SHA-512", %w[pss_sha512], %w[root_rsa], "example.com", NOW, "ok"],
  ["RSA-PSS, hash parameters absent rather than NULL", %w[pss_no_null], %w[root_rsa], "example.com", NOW, "ok"],
  ["RSA-PSS intermediate (SHA-384), ECDSA leaf", %w[leaf inter_pss], %w[root_rsa], "example.com", NOW, "ok"],
  ["RSA-PSS, signature changed", %w[pss_bad_sig], %w[root_rsa], "example.com", NOW, "BadSignature"],
  ["RSA-PSS, a 20-byte salt with SHA-256", %w[pss_salt20], %w[root_rsa], "example.com", NOW, "UnsupportedAlgorithm", "OpenSSL takes any salt length; tls/x509, as Go, wants the hash's"],
  ["RSA-PSS, MGF1 over SHA-1 with SHA-256", %w[pss_mgf_sha1], %w[root_rsa], "example.com", NOW, "UnsupportedAlgorithm", "OpenSSL takes another MGF1 hash; tls/x509, as Go, wants the same"],
  ["RSA-PSS, the defaults (SHA-1)", %w[pss_defaults], %w[root_rsa], "example.com", NOW, "UnsupportedAlgorithm", "OpenSSL takes SHA-1 here"],
  ["RSA-PSS, trailer 2", %w[pss_trailer2], %w[root_rsa], "example.com", NOW, "BadDer"],
  ["RSA-PSS, something after the parameters", %w[pss_junk], %w[root_rsa], "example.com", NOW, "BadDer"],
  ["certificatePolicies with a CPS qualifier", %w[ok_policies inter], %w[root_rsa], "example.com", NOW, "ok"],
  ["more than 64 extensions", %w[bad_many_extensions inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL has no limit; a limit keeps the check for repeats small"],
  ["a policy twice", %w[bad_policy_twice inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL does not parse policies it is not asked about"],
  ["a policy qualifier without its OID", %w[bad_policy_qualifier inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL does not parse policies it is not asked about"],
  ["an empty list of policy qualifiers", %w[bad_policy_no_qualifiers inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL does not parse policies it is not asked about"],
  ["keyUsage with a trailing zero byte", %w[ok_ku inter], %w[root_rsa], "example.com", NOW, "ok"],
  ["an element with tag 0 (end-of-contents) in subjectAltName", %w[bad_tag0 inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes a SAN entry it does not know"],
  ["GeneralizedTime before 2050", %w[bad_gentime inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes either kind of time for any year"],
  ["version v1 written out", %w[bad_version0 inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes a default written out, and extensions in a v1 certificate"],
  ["version 4 (3)", %w[bad_version3 inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes versions it does not know"],
  ["something after the version", %w[bad_version_extra inter], %w[root_rsa], "example.com", NOW, "BadDer"],
  ["a negative serial number", %w[bad_serial_negative inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes negative serials (Go 1.23 refuses them)"],
  ["a serial number with a needless zero", %w[bad_serial_long_form inter], %w[root_rsa], "example.com", NOW, "BadDer"],
  ["pathLenConstraint on a leaf", %w[bad_pathlen_leaf inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes it"],
  ["subjectAltName twice", %w[bad_duplicate_san inter], %w[root_rsa], "example.com", NOW, "BadDer"],
  ["keyUsage with unused bits set", %w[bad_ku_unused_bits inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL ignores the unused bits"],
  ["keyUsage of more than nine bits", %w[bad_ku_too_long inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL takes it"],
  ["an extension OID not in canonical form", %w[bad_oid inter], %w[root_rsa], "example.com", NOW, "BadDer"],
  ["certificatePolicies that do not parse", %w[bad_policies inter], %w[root_rsa], "example.com", NOW, "BadDer", "OpenSSL does not parse policies it is not asked about"],
  ["something after the extensions", %w[bad_ext_wrapper inter], %w[root_rsa], "example.com", NOW, "BadDer"],
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
  ["root of the same name, another key", %w[leaf inter], %w[other_root], "example.com", NOW, "BadSignature", "OpenSSL also matches issuers by key identifier, so it finds none: unknown issuer"],
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

bad.each { |n, der| c[n] = der }
pss.each { |n, der| c[n] = der }
c["ok_ku"] = ok_ku
c["ok_policies"] = ok_policies

# OpenSSL's verify errors that mean each answer: the oracle must fail for
# the same reason, not only fail.
V = OpenSSL::X509
REASONS = {
  "Expired" => [V::V_ERR_CERT_HAS_EXPIRED],
  "NotYetValid" => [V::V_ERR_CERT_NOT_YET_VALID],
  "UnknownIssuer" => [V::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, V::V_ERR_UNABLE_TO_GET_ISSUER_CERT, V::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, V::V_ERR_SELF_SIGNED_CERT_IN_CHAIN],
  "BadSignature" => [V::V_ERR_CERT_SIGNATURE_FAILURE],
  "NotCA" => [V::V_ERR_INVALID_CA],
  "PathLenExceeded" => [V::V_ERR_PATH_LENGTH_EXCEEDED],
  # OpenSSL calls an issuer without keyCertSign no CA at all.
  "BadKeyUsage" => [V::V_ERR_KEYUSAGE_NO_CERTSIGN, V::V_ERR_INVALID_PURPOSE, V::V_ERR_INVALID_CA],
  "BadExtKeyUsage" => [V::V_ERR_INVALID_PURPOSE],
  "UnknownCriticalExtension" => [V::V_ERR_UNHANDLED_CRITICAL_EXTENSION],
}
load = ->(x) { x.is_a?(String) ? OpenSSL::X509::Certificate.new(x) : x }
cases.each do |name, chain, roots, host, now, want, differs|
  next if differs
  verdict = begin
    store = OpenSSL::X509::Store.new
    roots.each { |r| store.add_cert(load.(c.fetch(r))) }
    store.purpose = OpenSSL::X509::PURPOSE_SSL_SERVER
    store.time = Time.at(now)
    leaf = load.(c.fetch(chain[0]))
    ctx = OpenSSL::X509::StoreContext.new(store, leaf, chain[1..].map { |x| load.(c.fetch(x)) })
    if !ctx.verify then [:fails, ctx.error]
    elsif !OpenSSL::SSL.verify_certificate_identity(leaf, host) then [:fails, :host]
    else [:ok]
    end
  rescue OpenSSL::X509::CertificateError, OpenSSL::ASN1::ASN1Error
    [:fails, :parse]
  end
  agree =
    case want
    when "ok" then verdict == [:ok]
    when "HostMismatch" then verdict == [:fails, :host]
    when "BadDer" then verdict[0] == :fails
    else verdict[0] == :fails && REASONS.fetch(want).include?(verdict[1])
    end
  abort "OpenSSL says #{verdict.inspect} for #{name}, want #{want}" unless agree
end

lit = ->(x) { "\"#{x}\"" }
out = +"// The test PKI: name, DER.\nfn certs() [#{c.size}]Named {\n    return [#{c.size}]Named{\n"
c.each { |n, x| out << "        Named{ .name = #{lit.(n)}, .der = #{lit.((x.is_a?(String) ? x : x.to_der).unpack1('H*'))} },\n" }
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
