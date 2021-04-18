(use ../janetjose/internal)
(use ../janetjose)
(use testament)

(def testcase-secret "test-secret-here")
(def testcase "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.265XFZvpRhfYCPjAvO4PJ4enxA9GBtInY7OJfSfqmj0")
(def test-header {"alg" "HS256" "typ" "JWT"})
(def test-payload {"sub" "1234567890" "name" "John Doe" "iat" 1516239022})
(def test-before-signature "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
(def test-signature "265XFZvpRhfYCPjAvO4PJ4enxA9GBtInY7OJfSfqmj0")

(deftest decoding
  (def result (decode testcase))
  (is (deep= test-header (result :header)))
  (is (deep= test-payload (result :payload)))
  (is (deep= test-before-signature (result :without-signature)))
  (is (deep= test-signature (result :signature)))
  )

(deftest hs256
  (def parsed (decode testcase))
  (is (verify-hs testcase-secret parsed))
  )

(deftest sign-and-unsign
  (def claims {:iat (os/time) :sub "NASA"})
  (def token (sign claims testcase-secret))
  (is (unsign token testcase-secret))
  )

(run-tests!)
