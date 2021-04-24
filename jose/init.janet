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

(defn jwks/empty [] @{})

(defn jwks/add [jwks key]
  (unless key (errorf "Key cannot be nil"))
  (def kid (get-in key [:jwk-public :kid]))
  (unless (get-in key [:jwk-public :alg]) (errorf "Algorithm missing in key with kid %p" kid))
  (put jwks kid key))

(defn jwk/hs [key &opt kid bits]
  (default kid :default)
  (default bits 256)
  (hs-key key kid bits))

(defn jwk/pem [pem &opt kid usage alg]
  (import-single-pem pem kid usage alg)
  )

(defn jwt/sign [data key]
  (cond
    (= :string (type key)) (sign-hs key data)
    (and (= (key :use) :sig) (= (key :type) :hmac)) (sign-hs key data)
    (and (= (key :use) :sig)) (sign-pk key data)
    (error "Key not supported for signature")
  ))

(defn jwt/unsign [token key]
  (try (unsign-hs key token) ([err] nil)))
