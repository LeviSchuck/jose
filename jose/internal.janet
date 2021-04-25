# Copyright (c) 2021 Levi Schuck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

(use janetls)
(import json)

(def md-algorithms {
  "HS256" :sha256
  "HS384" :sha384
  "HS512" :sha512
  "RS256" :sha256
  "RS385" :sha384
  "RS512" :sha512
  "PS256" :sha256
  "PS385" :sha384
  "PS512" :sha512
  "ES256" :sha256
  "ES385" :sha384
  "ES512" :sha512
  :hs256 :sha256
  :hs384 :sha384
  :hs512 :sha512
  :rs256 :sha256
  :rs384 :sha384
  :rs512 :sha512
  :ps256 :sha256
  :ps384 :sha384
  :ps512 :sha512
  :es256 :sha256
  :es384 :sha384
  :es512 :sha512
  :sha256 :sha256
  :sha384 :sha384
  :sha512 :sha512})


(def type-algorithms {
  "HS256" :hmac
  "HS384" :hmac
  "HS512" :hmac
  "RS256" :rsa-pkcs1-v1.5
  "RS385" :rsa-pkcs1-v1.5
  "RS512" :rsa-pkcs1-v1.5
  "PS256" :rsa-pkcs1-v2.1
  "PS385" :rsa-pkcs1-v2.1
  "PS512" :rsa-pkcs1-v2.1
  "ES256" :ecdsa
  "ES385" :ecdsa
  "ES512" :ecdsa
  })

(def type-to-type {
  :hmac :hmac
  :rsa-pkcs1-v1.5 :rsa
  :rsa-pkcs1-v2.1 :rsa
  :ecdsa :ecdsa
  })

(def kty-algorithms {
  "HS256" :hmac
  "HS384" :hmac
  "HS512" :hmac
  "RS256" :rsa
  "RS385" :rsa
  "RS512" :rsa
  "PS256" :rsa
  "PS385" :rsa
  "PS512" :rsa
  "ES256" :ecdsa
  "ES385" :ecdsa
  "ES512" :ecdsa
  })

(def rsa-version{
  "RS256" :pkcs1-v1.5
  "RS385" :pkcs1-v1.5
  "RS512" :pkcs1-v1.5
  "PS256" :pkcs1-v2.1
  "PS385" :pkcs1-v2.1
  "PS512" :pkcs1-v2.1
  })

(def type-usage {
  "sig" :sig
  :sig :sig
  "enc" :enc
  :enc :enc
})

(defn find-component [jwk options]
  (reduce |(if $0 $0 (if-let [c (get jwk $1)] c)) nil options))

(defn b64-encode [content] (if content (base64/encode content :url-unpadded)))
(defn bignum-bytes [num] (if num (bignum/to-bytes num)))
