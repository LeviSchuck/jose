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
(use ./internal)
(import ./jwt)

(def jwt-hs256-header (b64-encode (json/encode {"alg" "HS256" "typ" "JWT"})))

(defn verify-hs [shared-secret jwt &opt header]
  (def {:without-signature body :signature signature} jwt)
  (def header (or header (jwt :header)))
  (def alg (md-algorithms (if header (or (find-component header [:alg "alg"]) "HS256") "HS256")))
  (def signature (base64/decode signature))
  (def expected (md/hmac alg shared-secret body :raw))
  (constant= signature expected))

(defn unsign-hs [shared-secret jwt]
  (def jwt (jwt/decode jwt))
  (def header (jwt :header))
  (unless (= (header "typ") "JWT") (error "Not a JWT"))
  (if (header "alg")
    (unless (md-algorithms (header "alg")) (error "Not a JWT or JWS")))
  (unless (verify-hs shared-secret jwt header) (error "Invalid Signature")) 
  (def claims (jwt :payload))
  # Janet os/time seems to be UTC epoch seconds
  (jwt/check-claims claims)
  claims)

(defn sign-hs [shared-secret claims &opt header]
  (def alg (md-algorithms (if header (or (find-component header [:alg "alg"])) "HS256")))
  (def header (if header
    (b64-encode (json/encode header))
    jwt-hs256-header))
  (def payload (string header "." (b64-encode (json/encode claims))))
  (def signature (md/hmac alg shared-secret payload :raw))
  (string payload "." (b64-encode signature)))

