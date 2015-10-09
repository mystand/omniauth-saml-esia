require 'base64'
require 'uuid'
require 'zlib'
require 'cgi'

def print_xml(xml)
  doc = REXML::Document.new(xml)
  formatter = REXML::Formatters::Pretty.new
  formatter.compact = false
  out = ''
  formatter.write(doc, out)
  out
end

module OmniAuth
  module Strategies
    class ESIA
      class AuthRequest
        def create(settings, params = {})
          uuid = '_' + UUID.new.generate
          time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.%LZ')
          request = <<-REQUEST
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
AssertionConsumerServiceURL="#{settings[:assertion_consumer_service_url]}"
Destination="#{settings[:idp_sso_target_url]}"
ForceAuthn="false"
ID="#{uuid}"
IsPassive="false"
IssueInstant="#{time}"
ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
Version="2.0">
<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">#{settings[:issuer]}</saml2:Issuer>
</saml2p:AuthnRequest>"
REQUEST
          ssl = Ssl::SslGem.new
          ssl_opts = { engine: '', dgst: 'sha1', dgst_arg: '' }

          doc = Nokogiri::XML::Document.parse(Nokogiri::XML::Document.parse(request, nil, "UTF-8").canonicalize_excl, nil, "UTF-8")

          request = ssl.sign_xml(doc.search_child('AuthnRequest', NAMESPACES['saml2p']).first, settings[:pkey_path], ssl_opts)
          doc = Nokogiri::XML::Document.parse(request, nil, 'UTF-8')
          doc.search_child('X509Certificate', NAMESPACES['ds']).first << open(settings[:idp_cert], &:read).gsub(/\-{2,}[^\-]+\-{2,}/,'').gsub(/\n\n+/, "\n").strip
          request = doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML).sub("\n", '')

          ssl.verify_xml request, ssl_opts

          params[:SAMLRequest] = Base64.strict_encode64(Zlib::Deflate.deflate(request, 9)[2..-5])
          params[:Signature]  = '-'
          params[:SigAlg]     = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'

          query = params.map do |kv|
            "#{kv[0]}=#{CGI.escape(kv[1])}"
          end.join('&')

          res = settings[:idp_sso_target_url] + '?' + query
          res
        end

        def sign_xml(xml, key_path)
          privkey = OpenSSL::PKey::RSA.new(open(key_path, &:read))
          Base64.encode64(privkey.sign(OpenSSL::Digest::SHA1.new, xml))
        end
      end
    end
  end
end
