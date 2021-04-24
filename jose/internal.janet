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

(def hs-jwt-algorithms {
  :sha256 "HS256"
  :sha384 "HS384"
  :sha512 "HS512"
})
(def hs-md-algorithms {
  :hs256 :sha256
  :hs384 :sha384
  :hs512 :sha512
  :sha256 :sha256
  :sha384 :sha384
  :sha512 :sha512
  "HS256" :sha256
  "HS384" :sha384
  "HS512" :sha512
})

(defn decode [str]
  (def [header payload signature] (string/split "." str))
  (freeze {:header (json/decode (base64/decode header))
   :payload (json/decode (base64/decode payload))
   :without-signature (string/slice str 0 (+ (length header) (length payload) 1))
   :signature signature
   }))

(defn verify-hs [shared-secret jwt &opt header]
  (def {:without-signature body :signature signature} jwt)
  (def header (or header (jwt :header)))
  (def alg (hs-md-algorithms (if header (or (header "alg") (header :alg)) "HS256")))
  (def signature (base64/decode signature))
  (def expected (md/hmac alg shared-secret body :raw))
  (constant= signature expected))

(defn- b64-encode [content] (base64/encode content :url-unpadded))

(def jwt-hs256-header (b64-encode (json/encode {"alg" "HS256" "typ" "JWT"})))

(defn unsign-hs [shared-secret jwt]
  (def jwt (decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (if (header "alg")
    (unless (hs-md-algorithms (header "alg")) (error "Not an HMAC JWT")))
  (unless (verify-hs shared-secret jwt header) (error "Invalid Signature")) 
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (def time (os/time))
  (if (claims "exp")
    (when (>= time (claims "exp")) (error "Expired")))
  (if (claims "nbf")
    (when (< time (claims "nbf")) (error "Not Before")))
  claims)

(defn sign-hs [shared-secret claims &opt header]
  (def alg (hs-md-algorithms (if header (or (header "alg") (header :alg)) "HS256")))
  (def header (if header
    (b64-encode (json/encode header))
    jwt-hs256-header))
  (def payload (string header "." (b64-encode (json/encode claims))))
  (def signature (md/hmac alg shared-secret payload :raw))
  (string payload "." (b64-encode signature)))
