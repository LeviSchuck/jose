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
(use ./internal)
(import ./jwk-fingerprint :as fingerprint)
(use janetls)

(defn hs-alg [bits]
  (unless (or (= 256 bits) (= 384 bits) (= 512 bits))
    (error "HMAC bits must be 256 or 384 or 512"))
  (string "HS" bits))

(defn import-hs [components kid usage alg]
  (if alg (unless (= :hmac (kty-algorithms alg))
    (errorf "The algorithm %p cannot be used with an HMAC key" alg)))
  (def jwk-public
    (fingerprint/add-public @{
      :kid kid
      :kty "oct"
      :use usage
      :alg alg
     }))
  (def key-material (get components :key))
  (def jwk-private
    (merge jwk-public @{
      :k (b64-encode key-material)
    }))
  @{
    :jwk-private jwk-private
    :jwk-public jwk-public
    :key key-material
    :type :hmac
    :use usage
    })

(defn import-rsa [components kid usage alg]
  (if alg (unless (= :rsa (kty-algorithms alg))
    (errorf "The algorithm %p cannot be used with an RSA key" alg)))
  (def jwk-public
    (fingerprint/add-public @{
      :kid kid
      :kty "RSA"
      :use usage
      :alg alg
      :n (b64-encode (bignum-bytes (get components :n)))
      :e (b64-encode (bignum-bytes (get components :e)))
     }))
  (def jwk-private
    (merge jwk-public @{
      # Private Exponent
      :d (b64-encode (bignum-bytes (get components :d)))
      # First Prime Factor
      :p (b64-encode (bignum-bytes (get components :p)))
      # Second Prime Factor
      :q (b64-encode (bignum-bytes (get components :q)))
      # First Factor CRT Exponent
      :dp (b64-encode (bignum-bytes (get components :dp)))
      # Second Factor CRT Exponent
      :dq (b64-encode (bignum-bytes (get components :dq)))
      # First CRT Coefficient, janetls uses qp instead
      # It will switch to qi later.
      :qi (b64-encode (bignum-bytes (or
        (get components :qi)
        (get components :qp))))
    }))
  (def pk (pk/import (merge components {:version :pkcs1-v1.5})))
  (def pk-pss (pk/import (merge components {:version :pkcs1-v2.1})))
  @{
    :jwk-private jwk-private
    :jwk-public jwk-public
    :key pk
    :key-pss pk-pss 
    :type :rsa
    :use usage
    })
  
(defn import-ecdsa [components kid usage alg]
  (if alg (unless (= :ecdsa (kty-algorithms alg))
    (errorf "The algorithm %p cannot be used with an ECDSA key" alg)))
  (def jwk-public
    (fingerprint/add-public @{
      :kid kid
      :kty "EC"
      :use usage
      :alg alg
      :x (b64-encode (bignum-bytes (get components :x)))
      :y (b64-encode (bignum-bytes (get components :y)))
      :crv (case (get components :curve-group)
        :secp256r1 "P-256"
        :secp384r1 "P-384"
        :secp521r1 "P-521"
        )
     }))
  (def jwk-private
    (merge jwk-public @{
      # ECC Private Key
      :d (b64-encode (get components :d))
    }))
  (def pk (pk/import components))
  @{
    :jwk-private jwk-private
    :jwk-public jwk-public
    :key pk
    :type :ecdsa
    :use usage
    })

(defn import-components [components &opt kid usage alg]
  # use (usage) is optional and may not be set. Do not default it
  (def key-type (get components :type))
  (unless key-type (error "The key type could not be determined"))
  (case key-type
    :rsa (import-rsa components kid usage alg)
    :ecdsa (import-ecdsa components kid usage alg)
    :hmac (import-hs components kid usage alg)))

(defn hs-key [key kid bits]
  (import-hs {:key key} kid :sig (hs-alg bits)))
