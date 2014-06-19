# OmniAuth ESIA

Стратегия для авторизации в ЕСИА

https://github.com/kinnalru/omniauth-saml-esia

## Requirements

* [OmniAuth](http://www.omniauth.org/) 1.0+
* Ruby 1.9.2

## Usage

Use the ESIA strategy as a middleware in your application:

```ruby
require 'omniauth'
use OmniAuth::Strategies::ESIA,
  :assertion_consumer_service_url     => "https://esia.s.rnd-soft.ru/SOAP/ACS",
  :issuer                             => "http://esia.s.rnd-soft.ru",
  :pkey_path                          => "#{Rails.root}/config/esia/rnds-key.key",
  :idp_cert                           => "#{Rails.root}/config/esia/rnds-cert.pem",
  :idp_sso_target_url                 => "https://esia.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO"
```

or in your Rails application:

in `Gemfile`:

```ruby
gem 'omniauth-esia'
```

and in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :esia,
    :assertion_consumer_service_url     => "https://esia.s.rnd-soft.ru/SOAP/ACS",
    :issuer                             => "http://esia.s.rnd-soft.ru",
    :pkey_path                          => "#{Rails.root}/config/esia/rnds-key.key",
    :idp_cert                           => "#{Rails.root}/config/esia/rnds-cert.pem",
    :idp_sso_target_url                 => "https://esia.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO"
end
```

or in your Rails application with devise:

in `Gemfile`:

```ruby
gem 'omniauth-esia'
```

and in `config/initializers/devise.rb`:

```ruby
Devise.setup do |config|
  config.omniauth :esia,
    :assertion_consumer_service_url     => "https://esia.s.rnd-soft.ru/SOAP/ACS",
    :issuer                             => "http://esia.s.rnd-soft.ru",
    :pkey_path                          => "#{Rails.root}/config/esia/rnds-key.key",
    :idp_cert                           => "#{Rails.root}/config/esia/rnds-cert.pem",
    :idp_sso_target_url                 => "https://esia.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO"
end
```

## Authors

Authored by Samoilenko Yuri

## License

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
