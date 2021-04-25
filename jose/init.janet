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
(import ./hmac :as hmac)
(import ./internal-key :as internal-key)
(import ./jwk :as jwk)
(import ./jwks :as jwks)
(import ./jwt :as jwt)
(import ./pk :as pk)

(use janetls)
(import json)


(defn jwk/hs [key &opt kid bits]
  (default bits 256)
  (internal-key/hs-key key kid bits))

(defn jwk/generate-hs [&opt bits kid]
  (default bits 256)
  (internal-key/hs-key (util/random 64) kid bits))

(defn jwk/pem [pem &opt kid usage alg]
  (pk/import-single-pem pem kid usage alg))

(defn jwk/jwk [jwk &opt kid usage alg]
  (jwk/import-single-jwk jwk kid usage alg))

(defn jwk/generate-rsa [&opt bits kid usage alg]
  (default bits 2048)
  (def rsa (pk/generate :rsa bits))
  (internal-key/import-components (pk/export rsa) kid usage alg))

(defn jwk/generate-ecdsa [&opt curve kid usage alg]
  (default curve :secp256r1)
  # TODO convert P-256 to :secp256r1, etc.
  (def ecdsa (pk/generate :ecdsa curve))
  (internal-key/import-components (pk/export ecdsa) kid usage alg))

(defn jwk/private [jwk] (get jwk :jwk-private))
(defn jwk/public [jwk] (get jwk :jwk-public))

(defn jwks/empty [] @{})

(defn jwks/add [jwks key]
  (unless key (errorf "Key cannot be nil"))
  (def kid (get-in key [:jwk-public :kid]))
  # TODO fingerprint key
  (put jwks kid key))

(defn jwks/import [jwks input]
  (def input (if (bytes? input) (json/decode input) input))
  (def keys (or (get input "keys") (get input :keys) []))
  (def keys (filter |(not (nil? $)) (map jwk/import-single-jwk keys)))
  (reduce jwks/add jwks keys))

(defn jwks/export-private [jwks]
  (def keys (map jwk/private (values jwks)))
  @{:keys keys})

(defn jwks/export-public [jwks]
  (def keys (map jwk/public (values jwks)))
  @{:keys keys})

(defn util/to-json-string [object &opt pretty]
  (default pretty false)
  (if pretty (json/encode object "  " "\n")
    (json/encode object)))

(defn jwt/sign [data key]
  (cond
    (= :string (type key)) (hmac/sign-hs key data)
    (and (= (key :use) :sig) (= (key :type) :hmac)) (hmac/sign-hs (key :key) data)
    (and (= (key :use) :sig)) (pk/sign-pk key data)
    (and (= nil (key :use))) (pk/sign-pk key data)
    (error "Key not supported for signature")
  ))

(defn jwt/unsign [token key]
  (cond
    (= :string (type key)) (try (hmac/unsign-hs key token) ([_] nil))
    (and (dictionary? key) (key :type)) (try (jwk/unsign-jwk key token) ([_] nil))
    (dictionary? key) (try (jwks/unsign-jwks key token) ([_] nil))
    (error "Key not supported for signature")
  ))

(defn jwt/unsign-unsafe [token key]
  (cond
    (= :string (type key)) (hmac/unsign-hs key token)
    (and (dictionary? key) (key :type)) (jwk/unsign-jwk key token)
    (dictionary? key) (jwks/unsign-jwks key token)
    (error "Key not supported for signature")
  ))
