require "time"
require "omniauth"
require "ruby-saml"
require 'rsa_ext'

module OmniAuth
  module Strategies
    class ESIA
      class AuthResponse

        ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
        PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
        DSIG      = "http://www.w3.org/2000/09/xmldsig#"

        attr_accessor :options, :response, :document, :settings

        def initialize(response, options = {})
          raise ArgumentError.new("Response cannot be nil") if response.nil?
          self.options  = options
          self.response = response

          OmniAuth.logger.debug "----1:#{options[:pkey_path]}"
          key = OpenSSL::PKey::RSA.new(open(options[:pkey_path], &:read))
          OmniAuth.logger.debug "----2:#{key}"
          #string = key.private_decrypt(Base64.decode64(response))
          @doc = Nokogiri::XML(Base64.decode64(response))
          @doc.remove_namespaces!

          cert1 = OpenSSL::X509::Certificate.new(Base64.decode64(@doc.css('X509Certificate')[0].text))
          cert2 = OpenSSL::X509::Certificate.new(Base64.decode64(@doc.css('X509Certificate')[1].text))

          OmniAuth.logger.debug "----3 check key: #{cert2.check_private_key(key)}"

          enc1 = Base64.decode64(@doc.css('CipherValue')[0].text)
          enc2 = Base64.decode64(@doc.css('CipherValue')[1].text)

          OmniAuth.logger.debug "----4 cipherkey key encrypted: #{enc1}"

          # Generate the key used for the cipher below via the RSA::OAEP algo
          rsak      = RSA::Key.new key.n, key.d

          OmniAuth.logger.debug "NEW RSA KEY:#{rsak}"

          cipherkey = RSA::OAEP.decode rsak, enc1

          OmniAuth.logger.debug "----5 cipherkey key DECRYPTED: #{cipherkey}"

          bytes  = enc2.bytes.to_a
          iv     = bytes[0...16].pack('c*')
          others = bytes[16..-1].pack('c*')

          cipher = OpenSSL::Cipher.new('AES-128-CBC')
          cipher.decrypt
          cipher.iv  = iv
          cipher.key = cipherkey

          @out = cipher.update(others)

          OmniAuth.logger.debug "----6 succesfuly decoded"
          OmniAuth.logger.debug "----7 result doc #{@out}"

          self.document = Nokogiri::XML(@out)
          self.document.remove_namespaces!
        end

        #def valid?
          #validate(soft = true)
        #end

        #def validate!
        #  validate(soft = false)
        #end

        # The value of the user identifier as designated by the initialization request response
        def name_id
          @name_id ||= self.document.css('NameID').first.text
        end

        # A hash of all the attributes with the response. Assuming there is only one value for each key
        def attributes
          @attr_statements ||= begin
            hash = {}
            self.document.css('AttributeStatement').children.each do |c|
              begin
                hash[c.attributes['FriendlyName'].value.strip.to_sym] = c.text.strip
              rescue
              end
            end
            hash
          end
        end

        # When this user session should expire at latest
        #def session_expires_at
        #  @expires_at ||= begin
        #    node = xpath("/p:Response/a:Assertion/a:AuthnStatement")
        #    parse_time(node, "SessionNotOnOrAfter")
        #  end
        #end

        # Conditions (if any) for the assertion to run
        #def conditions
        #  @conditions ||= begin
        #    xpath("/p:Response/a:Assertion[@ID='#{signed_element_id}']/a:Conditions")
        #  end
        #end

        private

        def validation_error(message)
          raise OmniAuth::Strategies::ESIA::ValidationError.new(message)
        end

        def validate(soft = true)
          validate_response_state(soft) &&
          validate_conditions(soft)     &&
          document.validate(get_fingerprint, soft)
        end

        def validate_response_state(soft = true)
          if response.empty?
            return soft ? false : validation_error("Blank response")
          end

          if settings.nil?
            return soft ? false : validation_error("No settings on response")
          end

          if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
            return soft ? false : validation_error("No fingerprint or certificate on settings")
          end

          true
        end

        def get_fingerprint
          if settings.idp_cert
            cert = OpenSSL::X509::Certificate.new(settings.idp_cert.gsub(/^ +/, ''))
            Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          else
            settings.idp_cert_fingerprint
          end
        end

        def validate_conditions(soft = true)
          return true if conditions.nil?
          return true if options[:skip_conditions]

          if not_before = parse_time(conditions, "NotBefore")
            if Time.now.utc < not_before
              return soft ? false : validation_error("Current time is earlier than NotBefore condition")
            end
          end

          if not_on_or_after = parse_time(conditions, "NotOnOrAfter")
            if Time.now.utc >= not_on_or_after
              return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
            end
          end

          true
        end

        def parse_time(node, attribute)
          if node && node.attributes[attribute]
            Time.parse(node.attributes[attribute])
          end
        end

        def strip(string)
          return string unless string
          string.gsub(/^\s+/, '').gsub(/\s+$/, '')
        end

        def xpath(path)
          REXML::XPath.first(document, path, { "p" => PROTOCOL, "a" => ASSERTION })
        end

        def signed_element_id
          doc_id = document.signed_element_id
          doc_id[1, doc_id.size]
        end
      end
    end
  end
end
