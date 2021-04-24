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


(def type-algorithms
  {"HS256" :hmac
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
   "ES512" :ecdsa})

(def type-usage {
  "sig" :sig
  :sig :sig
  "enc" :enc
  :enc :enc
})

(defn- jwk-find-alg-sign [jwk]
  (def alg (get-in jwk [:jwk-public :alg]))
  (cond
    alg alg
    (= :string (type (get jwk :key))) "HS256"
    (do
      (def kind (get-in jwk [:key :type]))
      (def variant (or (get-in jwk [:key :version]) (get-in jwk [:key :curve-group])))
      (match [kind variant]
        [:rsa :pkcs1-v1.5] "RS256"
        [:rsa :pkcs1-v2.1] "PS256"
        [:ecdsa :secp256r1] "ES256"
        [:ecdsa :secp384r1] "ES384"
        [:ecdsa :secp521r1] "ES512" # not a typo, the curve is 521
        [t v] (errorf "The key appears to be %p %p and this is not supported" t v)
        _ (error "This key appears to not be supported"))
        )))

(defn decode [str]
  (def [header payload signature] (string/split "." str))
  (freeze
   {:header (json/decode (base64/decode header))
    :payload (json/decode (base64/decode payload))
    :without-signature (string/slice str 0 (+ (length header) (length payload) 1))
    :signature signature
    }))


(defn verify-hs [shared-secret jwt &opt header]
  (def {:without-signature body :signature signature} jwt)
  (def header (or header (jwt :header)))
  (def alg (md-algorithms (if header (or (header "alg") (header :alg)) "HS256")))
  (def signature (base64/decode signature))
  (def expected (md/hmac alg shared-secret body :raw))
  (constant= signature expected))




(defn verify-pk [jwk jwt &opt header]
  (def {:without-signature body :signature signature} jwt)
  (def header (or header (jwt :header)))
  (def digest (md-algorithms (if header (or (header "alg") (header :alg)) "RS256")))
  (def key (get jwk :key))
  (pk/verify key body signature {
    :digest digest
    :encoding :base64
    :encoding-variant :url-unpadded
    }))

(defn- b64-encode [content] (base64/encode content :url-unpadded))

(def jwt-hs256-header (b64-encode (json/encode {"alg" "HS256" "typ" "JWT"})))

(defn- check-claims [claims now]
  (if (claims "exp")
    (when (>= now (claims "exp")) (error "Expired")))
  (if (claims "nbf")
    (when (< now (claims "nbf")) (error "Not Before")))
  )

(defn unsign-hs [shared-secret jwt]
  (def jwt (decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (if (header "alg")
    (unless (md-algorithms (header "alg")) (error "Not a JWT or JWS")))
  (unless (verify-hs shared-secret jwt header) (error "Invalid Signature")) 
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (check-claims claims (os/time))
  claims)

(defn sign-hs [shared-secret claims &opt header]
  (def alg (md-algorithms (if header (or (header "alg") (header :alg)) "HS256")))
  (def header (if header
    (b64-encode (json/encode header))
    jwt-hs256-header))
  (def payload (string header "." (b64-encode (json/encode claims))))
  (def signature (md/hmac alg shared-secret payload :raw))
  (string payload "." (b64-encode signature)))

(defn sign-pk [key claims &opt header]
  (def alg (if header (or (header "alg") (header :alg))))
  # If not present, then detect the algorithm for the signature
  (def alg (if alg alg (jwk-find-alg-sign key)))
  (unless alg (error "The algorithm for this sign operation could not be determined"))
  # TODO ensure the algorithm is consistent with the key type
  (def digest (md-algorithms alg))
  (def header (if header
    (b64-encode (json/encode header))
    (b64-encode (json/encode {
      :alg alg
      :typ "JWT"
      :kid (get-in key [:jwt-public :kid])
    }))))
  (def payload (string header "." (b64-encode (json/encode claims))))
  (def signature (pk/sign (key :key) payload {
    :digest digest
    :encoding :base64
    :encoding-variant :url-unpadded
    }))
  (string payload "." signature))

(defn unsign-pk [jwk jwt]
  (def jwt (decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (if (header "alg")
    (unless (md-algorithms (header "alg")) (error "Not a JWT or JWS")))
  (unless (verify-pk jwk jwt header) (error "Invalid Signature"))
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (check-claims claims (os/time))
  claims)

(defn hs-key [key kid bits]
  (unless (or (= 256 bits) (= 384 bits) (= 512 bits))
    (error "HMAC bits must be 256 or 384 or 512"))
  (def jwk-public
    {:kid kid
     :kty :oct
     :use :sig
     :alg (string "HS" bits)
     })
  (def jwk-private (merge jwk-public {:k key}))
  {:jwk-private jwk-private
   :jwk-public jwk-public
   :key (b64-encode key)
   :type :hmac
   :use :sig
   })



(defn- import-single [key &opt kid usage alg]
  # use (usage) is optional and may not be set. Do not default it
  (def key-type (get key :type))
  (unless key-type (error "The key type could not be determined"))
  # https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
  # There's no defined mapping to bit sizes for RSA
  (def kind (key :type))
  (def variant (or (key :version) (key :curve-group)))
  (def expected-type
    (match [kind variant]
      [:rsa :pkcs1-v1.5] :rsa-pkcs1-v1.5
      [:rsa :pkcs1-v2.1] :rsa-pkcs1-v2.1
      [:ecdsa _] :ecdsa
      _ (error "This key appears to not be supported")
      ))

  # The message digest match only matters if the usage is for
  # signing.
  (if (and (= usage :sig) alg)
    (unless (get md-algorithms alg) (errorf "The algorithm %p is not supported" alg)))

  (def desired-type (if alg (get type-algorithms alg)))

  (def exported-key (pk/export key))

  # Ensure the algorithms line up, reconfigure if necessary
  (def key (cond
             (and (= :rsa-pkcs1-v1.5 expected-type) (= :rsa-pkcs1-v2.1 desired-type))
             # Switch up from v1.5 to v2.1, this requires a re-import
             # This happens if PS256 is used for example.
             (pk/import (merge exported-key {:version :pkcs1-v2.1}))
             # Leave it alone if no alg is specified which binds to a type
             (= desired-type nil)
             key
             # HS256 can't be used on an RSA or ECDSA key, nor an ES256 for an RSA key, etc.
             (not= expected-type desired-type)
             (errorf "The type %p cannot be used on this key which is type %p" desired-type expected-type)
             # No change, keep key as is
             key))
  # kty is required
  (def kty (case (or desired-type expected-type)
             :hash "oct"
             :ecdsa "EC"
             :rsa-pkcs1-v1.5 "RSA"
             :rsa-pkcs1-v2.1 "RSA"
             nil))
  (unless kty (errorf "The key type could not be determined from the type %p" desired-type))
  (def curve (case variant
               :secp256r1 "P-256"
               :secp384r1 "P-384"
               :secp521r1 "P-521"
               nil
               ))
  (def jwk-public
    {:kid kid
     :kty kty
     :use usage
     :alg alg
     :crv curve
     :x (if (exported-key :x) (b64-encode (:to-bytes (exported-key :x))))
     :y (if (exported-key :y) (b64-encode (:to-bytes (exported-key :y))))
     :n (if (exported-key :n) (b64-encode (:to-bytes (exported-key :n))))
     :e (if (exported-key :e) (b64-encode (:to-bytes (exported-key :e))))
     })
  (def jwk-private
    (merge jwk-public
           {:d (if (exported-key :d) (b64-encode (if
            (= :janetls/bignum (type (exported-key :d)))
            (b64-encode (:to-bytes (exported-key :d)))
            (b64-encode (exported-key :p)))))
            :p (if (exported-key :p) (b64-encode (:to-bytes (exported-key :p))))
            :q (if (exported-key :q) (b64-encode (:to-bytes (exported-key :q))))
            :dp (if (exported-key :dp) (b64-encode (:to-bytes (exported-key :dp))))
            :dq (if (exported-key :dq) (b64-encode (:to-bytes (exported-key :dq))))
            :qi (if (exported-key :qi) (b64-encode (:to-bytes (exported-key :qi))))
           }))
  {:jwk-private jwk-private
   :jwk-public jwk-public
   :key key
   :type desired-type
   :use usage
   })

(defn import-single-pem [pem &opt kid usage alg]
  (def key (pk/import {:pem pem}))
  (freeze (import-single key kid usage alg)))

(defn- component-to-bytes [jwk component] (put jwk component (base64/decode (get jwk component))))
(defn- component-to-bignum [jwk component] (put jwk component (bignum/parse-bytes (base64/decode (get jwk component)))))

(defn import-single-jwk [jwk &opt kid usage alg]
  # Convert from a json string to a structure
  (def jwk (if (= :string (type jwk)) (json/decode jwk) jwk))
  (def jwk (merge jwk {:type (case (jwk "kty")
    "RSA" :rsa
    "EC" :ecdsa
    )}))

  (def jwk (reduce (fn [jwk component]
    (case component
    "d" (component-to-bignum jwk component)
    "n" (component-to-bignum jwk component)
    "e" (component-to-bignum jwk component)
    "q" (component-to-bignum jwk component)
    "p" (component-to-bignum jwk component)
    "qi" (component-to-bignum jwk component)
    "dp" (component-to-bignum jwk component)
    "dq" (component-to-bignum jwk component)
    "x" (component-to-bignum jwk component)
    "y" (component-to-bignum jwk component)
    "k" (component-to-bytes jwk component)
    jwk
    )) jwk (keys jwk)))
  # Attempt to import it
  (def key (pk/import jwk))
  # Get other details in line
  (def kid (or kid (get jwk :kid) (get jwk "kid")))
  (def usage (or usage (get jwk :use) (get jwk "use")))
  (def alg (or alg (get jwk :alg) (get jwk "alg")))
  # normalize the usage type into a keyword
  (def usage (if usage (type-usage usage)))

  (freeze (import-single key kid usage alg)))
