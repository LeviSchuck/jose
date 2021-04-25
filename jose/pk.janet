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

(import ./internal :prefix "")
(import ./jwt :as jwt)
(import ./internal-key :as internal-key)
(use janetls)
(import json)

(defn- default-key-algorithm [jwk]
  (def alg (get-in jwk [:jwk-public :alg]))
  (cond
    alg alg
    (= :string (type (get jwk :key))) "HS256"
    (do
      (def kind (get-in jwk [:key :type]))
      (def variant (case kind
        :rsa (get-in jwk [:key :version])
        :ecdsa (get-in jwk [:key :curve-group])))
      (match [kind variant]
        [:rsa :pkcs1-v1.5] "RS256"
        [:rsa :pkcs1-v2.1] "PS256"
        [:ecdsa :secp256r1] "ES256"
        [:ecdsa :secp384r1] "ES384"
        [:ecdsa :secp521r1] "ES512" # not a typo, the curve is 521
        [t v] (errorf "The key appears to be %p %p and this is not supported" t v)
        _ (errorf "This key appears to not be supported %p %p" kind variant))
        )))

(defn verify-pk [jwk jwt &opt header]
  (def {:without-signature body :signature signature} jwt)
  (def header (or header (jwt :header)))
  (def alg (or (find-component header [:alg "alg"]) "RS256"))
  (def digest (md-algorithms (if header alg)))
  (def sign-key (case (rsa-version alg)
    :pkcs1-v2.1 (jwk :key-pss)
    :pkcs1-v1.5 (jwk :key)
    (jwk :key)
    ))

  (pk/verify sign-key body signature {
    :digest digest
    :encoding :base64
    :encoding-variant :url-unpadded
    }))

(defn sign-pk [key claims &opt header]
  (def alg (if header (or (find-component header [:alg "alg"]))))
  # If not present, then detect the algorithm for the signature
  (def alg (if alg alg (default-key-algorithm key)))
  (unless alg (error "The algorithm for this sign operation could not be determined"))
  # TODO ensure the algorithm is consistent with the key type
  (def digest (md-algorithms alg))
  (def header (if header
    (b64-encode (json/encode header))
    (b64-encode (json/encode {
      :alg alg
      :typ "JWT"
      :kid (get-in key [:jwk-public :kid])
    }))))
  (def payload (string header "." (b64-encode (json/encode claims))))
  # TODO verify selected alg against alg in JWK
  (def sign-key (case (rsa-version alg)
    :pkcs1-v2.1 (key :key-pss)
    :pkcs1-v1.5 (key :key)
    (key :key)
    ))
  (def signature (pk/sign sign-key payload {
    :digest digest
    :encoding :base64
    :encoding-variant :url-unpadded
    }))
  (string payload "." signature))

(defn unsign-pk [jwk jwt]
  (def jwt (jwt/decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (if (header "alg")
    (unless (md-algorithms (header "alg")) (error "Not a JWT or JWS")))
  (unless (verify-pk jwk jwt header) (error "Invalid Signature"))
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (jwt/check-claims claims (os/time))
  claims)

(defn import-single-pem [pem &opt kid usage alg]
  (def key (pk/import {:pem pem}))
  (def components (pk/export key))
  (freeze (internal-key/import-components components kid usage alg)))
