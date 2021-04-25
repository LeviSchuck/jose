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
(import json)


(defn jwk/hs [key &opt kid bits]
  (default kid :default)
  (default bits 256)
  (hs-key key kid bits))

(defn jwk/pem [pem &opt kid usage alg]
  (import-single-pem pem kid usage alg))

(defn jwk/jwk [jwk &opt kid usage alg]
  (import-single-jwk jwk kid usage alg))

# TODO JWK generate new jwk function

(defn jwk/private [jwk] (get jwk :jwk-private))
(defn jwk/public [jwk] (get jwk :jwk-public))

(defn jwks/empty [] @{})

(defn jwks/add [jwks key]
  (unless key (errorf "Key cannot be nil"))
  (def kid (get-in key [:jwk-public :kid]))
  (put jwks kid key))

(defn jwks/import [jwks input]
  (def input (if (= :string (type input)) (json/decode input) input))
  (def keys (get input "keys" []))
  (def keys (map import-single-jwk keys))
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
    (= :string (type key)) (sign-hs key data)
    (and (= (key :use) :sig) (= (key :type) :hmac)) (sign-hs key data)
    (and (= (key :use) :sig)) (sign-pk key data)
    (and (= nil (key :use))) (sign-pk key data)
    (error "Key not supported for signature")
  ))

(defn jwt/unsign [token key]
  (cond
    (= :string (type key)) (try (unsign-hs key token) ([err] nil))
    (and (= (key :use) :sig) (= (key :type) :hmac)) (try (unsign-hs (key :key) token) ([err] nil))
    (and (= (key :use) :sig)) (try (unsign-pk key token) ([err] nil))
    (and (= nil (key :use))) (try (unsign-pk key token) ([err] nil))
    (key :keys) nil # This is a JWK TODO
    (error "Key not supported for signature")
  ))

(defn jwt/unsign-unsafe [token key]
  (cond
    (= :string (type key)) (unsign-hs key token)
    (and (= (key :use) :sig) (= (key :type) :hmac)) (unsign-hs (key :key) token)
    (and (= (key :use) :sig)) (unsign-pk key token)
    (key :keys) nil # This is a JWK TODO
    (and (= nil (key :use))) (unsign-pk key token)
    (error "Key not supported for signature")
  ))
