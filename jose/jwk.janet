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
(import ./internal :prefix "")
(import json)
(import ./internal-key :as internal-key)
(import ./hmac :as hmac)
(import ./pk :as pk)
(import ./jwt :as jwt)

(defn- component-to-bytes [jwk component] (put jwk component (base64/decode (get jwk component))))
(defn- component-to-bignum [jwk component] (put jwk component (bignum/parse-bytes (base64/decode (get jwk component)))))

(defn- curve-group-of-jwk [jwk] (case (find-component jwk [:crv "crv"])
  "P-256" :secp256r1
  "P-384" :secp384r1
  "P-521" :secp521r1
  ))

# This is for janetls
(defn- type-of-jwk [jwk] (case (find-component jwk [:kty "kty"])
    "RSA" :rsa
    "EC" :ecdsa
    :oct :hmac
    "oct" :hmac # TODO This can totally differ if its AES for example.
    ))

(defn- jwk-component-to-bytes [jwk & options]
  (if-let [c (find-component jwk options)]
    (base64/decode c)
  ))

(defn- jwk-component-to-bignum [jwk & options]
  (if-let [c (find-component jwk options)]
    (bignum/parse-bytes (base64/decode c))
  ))

(defn- jwk-to-rsa-components [jwk] {
  :type :rsa
  # Public Parameters
  :n (jwk-component-to-bignum jwk :n "n")
  :e (jwk-component-to-bignum jwk :e "e")
  # Private Parameters
  :p (jwk-component-to-bignum jwk :p "p")
  :q (jwk-component-to-bignum jwk :q "q")
  :d (jwk-component-to-bignum jwk :d "d")
  })

(defn- jwk-to-ecdsa-components [jwk] {
  :type :ecdsa
  :curve-group (curve-group-of-jwk jwk)
  # Public Parameters
  :x (jwk-component-to-bignum jwk :x "x")
  :y (jwk-component-to-bignum jwk :y "y")
  # Private Parameters
  :d (jwk-component-to-bytes jwk :d "d")
  })

(defn import-single-jwk [jwk &opt kid usage alg]
  # Convert from a json string to a structure
  (def jwk (if (= :string (type jwk)) (json/decode jwk) jwk))
  (def jwk-type (type-of-jwk jwk))
  (unless jwk-type (error "Could not determine the type from the JWK"))
 
  # Get other details in line
  (def kid (or kid (find-component jwk [:kid "kid"])))
  (def usage (or usage (find-component jwk [:use "use"])))
  (def alg (or alg (find-component jwk [:alg "alg"])))
  # normalize the usage type into a keyword
  (def usage (if usage (type-usage usage)))
  # Attempt to import
  (def components (case jwk-type
    :rsa (jwk-to-rsa-components jwk)
    :ecdsa (jwk-to-ecdsa-components jwk)
    :hmac @{
      :key (jwk-component-to-bytes jwk :k "k")
      :type :hmac
      }
    ))
  (if components (freeze (internal-key/import-components components kid usage alg)))
  )

(defn verify-jwk [jwk jwt]
  (case (jwk :type)
    :hmac (hmac/verify-hs (jwk :key) jwt)
    :ecdsa (pk/verify-pk jwk jwt)
    :rsa (pk/verify-pk jwk jwt)
    (errorf "Unsupported JWK type %p" (jwk :type))
  ))

(defn unsign-jwk [jwk jwt]
  (def jwt (jwt/decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (unless (verify-jwk jwk jwt) (error "Invalid Signature"))
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (jwt/check-claims claims (os/time))
  claims)

