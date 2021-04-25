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

# https://tools.ietf.org/html/rfc7638
(defn- fingerprint-sym [jwk]
  (def buf (buffer))
  (buffer/push-string buf "{\"k\":")
  (json/encode (get-in jwk [:jwk-public :k]) buf)
  (buffer/push-string buf ",\"kty\":")
  (json/encode (get-in jwk [:jwk-public :kty]) buf)
  (buffer/push-string buf "}")
  (md/digest :sha256 buf :base64 :url-unpadded))

(defn- fingerprint-rsa [jwk]
  (def buf (buffer))
  (buffer/push-string buf "{\"e\":")
  (json/encode (get-in jwk [:jwk-public :e]) buf)
  (buffer/push-string buf ",\"kty\":")
  (json/encode (get-in jwk [:jwk-public :kty]) buf)
  (buffer/push-string buf ",\"n\":")
  (json/encode (get-in jwk [:jwk-public :n]) buf)
  (buffer/push-string buf "}")
  (md/digest :sha256 buf :base64 :url-unpadded))

(defn- fingerprint-ecdsa [jwk]
  (def buf (buffer))
  (buffer/push-string buf "{\"crv\":")
  (json/encode (get-in jwk [:jwk-public :e]) buf)
  (buffer/push-string buf ",\"kty\":")
  (json/encode (get-in jwk [:jwk-public :kty]) buf)
  (buffer/push-string buf ",\"x\":")
  (json/encode (get-in jwk [:jwk-public :x]) buf)
  (buffer/push-string buf ",\"y\":")
  (json/encode (get-in jwk [:jwk-public :y]) buf)
  (buffer/push-string buf "}")
  (md/digest :sha256 buf :base64 :url-unpadded))

(defn fingerprint [jwk]
  (def kind (jwk :type))
  (cond
    (= :hmac kind) (fingerprint-sym jwk)
    (= :rsa kind) (fingerprint-rsa jwk)
    (= :ecdsa kind) (fingerprint-ecdsa jwk)
    (errorf "Cannot fingerprint key, the type %p appears unsupported" kind)
  ))

(defn add [jwk]
  (if (get-in jwk [:jwk-public :kid])
    # Has a kid, no need to add fingerprint
    jwk
    # No Key ID found, determine one.
    (do
      (def kid (fingerprint jwk))
      (put-in jwk [:jwk-public :kid] kid)
      (put-in jwk [:jwk-private :kid] kid))
    ))

(defn add-public [jwk]
  (if (get jwk :kid)
    # Has a kid, no need to add fingerprint
    jwk
    # No Key ID found, determine one.
    (do
      (def kid (fingerprint jwk))
      (put jwk :kid kid)
      (put jwk :kid kid))
    ))
