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
(import ./jwk :as jwk)
(import ./jwt :as jwt)


(defn verify-jwks [jwks jwt]
  (def {
    :without-signature body
    :signature signature
    :header header
    } jwt)
  (def alg (or (get header :alg) (get header "alg")))
  (def kid (or (get header :kid) (get header "kid")))
  (def typ (or (get header :typ) (get header "typ")))
  (unless (= typ "JWT") (error "Not a JWT"))
  (unless alg (error "JWT missing alg"))
  (def kind (get type-algorithms alg))
  (unless kind (errorf "Alg %p not supported" alg))
  (def kty (get kty-algorithms alg))
  (unless kty (errorf "Alg %p not supported" alg))
  (if kid 
    (do
      (def jwk (get jwks kid))
      (unless jwk (errorf "Key with kid %p not found in JWK Set" kid))
      (jwk/verify-jwk jwk jwt))
    (reduce (fn [result jwk] (if result result (if 
      # Only attempt to verify if the overall type (rsa or ecdsa)
      # is a match
      (= (get jwk :type) kty)
      # Suppress any error, as failures will propegate with an error
      # message
      (try (jwk/verify-jwk jwk jwt) ([_] nil))
      ))) nil (values jwks))
    ))

(defn unsign-jwks [jwks jwt]
  (def jwt (jwt/decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (unless (verify-jwks jwks jwt) (error "Invalid Signature"))
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (jwt/check-claims claims (os/time))
  claims)