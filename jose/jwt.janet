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

(import json)
(use janetls)

(defn check-claims [claims & now]
  (default now (os/time))
  (if (claims "exp")
    (when (>= now (claims "exp"))
      (errorf "This token expired %d seconds ago"
        (- now (claims "exp")))))
  (if (claims "nbf")
    (when (< now (claims "nbf"))
      (errorf "This token is not valid yet, it will be in %d seconds"
        (- (claims "exp") now))))
  )

(defn decode [str]
  (def [header payload signature] (string/split "." str))
  (freeze
   {:header (json/decode (base64/decode header))
    :payload (json/decode (base64/decode payload))
    :without-signature (string/slice str 0 (+ (length header) (length payload) 1))
    :signature signature
    }))
