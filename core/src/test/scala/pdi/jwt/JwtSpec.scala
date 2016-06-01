package pdi.jwt

import pdi.jwt.algorithms._
import pdi.jwt.exceptions._

import scala.util.Success

class JwtSpec extends UnitSpec with Fixture {
  def battleTestEncode(d: DataEntryBase, key: String) = {
    assertResult(d.tokenEmpty, d.alg.fullName) { Jwt.encode(claim) }
    assertResult(d.token, d.alg.fullName) { Jwt.encode(d.header, claim, key, d.alg) }
    assertResult(d.token, d.alg.fullName) { Jwt.encode(claim, key, d.alg) }
    assertResult(d.tokenEmpty, d.alg.fullName) { Jwt.encode(claimClass) }
    assertResult(d.token, d.alg.fullName) { Jwt.encode(claimClass, key, d.alg) }
    assertResult(d.token, d.alg.fullName) { Jwt.encode(d.headerClass, claimClass, key) }
  }

  describe("Jwt") {
    it("should encode Hmac") {
      val mock = mockValidTime
      data foreach { d => battleTestEncode(d, secretKey) }
      mock.tearDown
    }

    it("should encode RSA") {
      val mock = mockValidTime
      dataRSA foreach { d => battleTestEncode(d, privateKeyRSA) }
      mock.tearDown
    }

    it("should be symetric") {
      val mock = mockValidTime
      data foreach { d =>
        assertResult((d.header, claim, d.signature), d.alg.fullName) {
          Jwt.decodeAll(Jwt.encode(d.header, claim, secretKey, d.alg), secretKey, JwtAlgorithm.allHmac).get
        }
      }

      dataRSA foreach { d =>
        assert({
          val (h, c, s) = Jwt.decodeAll(Jwt.encode(d.header, claim, randomRSAKey.getPrivate, d.alg.asInstanceOf[JwtRSAAlgorithm]), randomRSAKey.getPublic, JwtAlgorithm.allRSA).get

          h == d.header && c == claim
        }, d.alg.fullName)

        assert({
          val (h, c, s) = Jwt.decodeAll(Jwt.encode(d.header, claim, randomRSAKey.getPrivate, d.alg.asInstanceOf[JwtRSAAlgorithm]), randomRSAKey.getPublic).get

          h == d.header && c == claim
        }, d.alg.fullName)
      }

      dataECDSA foreach { d =>
        assert({
          val (h, c, s) = Jwt.decodeAll(Jwt.encode(d.header, claim, randomECKey.getPrivate, d.alg.asInstanceOf[JwtECDSAAlgorithm]), randomECKey.getPublic, JwtAlgorithm.allECDSA).get

          h == d.header && c == claim
        }, d.alg.fullName)
      }

      mock.tearDown
    }

    it("should decodeRawAll") {
      val mock = mockValidTime
      data foreach { d =>
        assertResult(Success((d.header, claim, d.signature)), d.alg.fullName) { Jwt.decodeRawAll(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(Success((d.header, claim, d.signature)), d.alg.fullName) { Jwt.decodeRawAll(d.token, secretKeyOf(d.alg)) }
      }
      mock.tearDown
    }

    it("should decodeRaw") {
      val mock = mockValidTime
      data foreach { d =>
        assertResult(Success((claim)), d.alg.fullName) { Jwt.decodeRaw(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(Success((claim)), d.alg.fullName) { Jwt.decodeRaw(d.token, secretKeyOf(d.alg)) }
      }
      mock.tearDown
    }

    it("should decodeAll") {
      val mock = mockValidTime
      data foreach { d =>
        assertResult(Success((d.header, claim, d.signature)), d.alg.fullName) { Jwt.decodeAll(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(Success((d.header, claim, d.signature)), d.alg.fullName) { Jwt.decodeAll(d.token, secretKeyOf(d.alg)) }
      }
      mock.tearDown
    }

    it("should decode") {
      val mock = mockValidTime
      data foreach { d =>
        assertResult(Success(claim), d.alg.fullName) { Jwt.decode(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(Success(claim), d.alg.fullName) { Jwt.decode(d.token, secretKeyOf(d.alg)) }
      }
      mock.tearDown
    }

    it("should validate correct tokens") {
      val mock = mockValidTime

      data foreach { d =>
        assertResult((), d.alg.fullName) { Jwt.validate(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult((), d.alg.fullName) { Jwt.validate(d.token, secretKeyOf(d.alg)) }
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, secretKeyOf(d.alg)) }
      }

      dataRSA foreach { d =>
        assertResult((), d.alg.fullName) { Jwt.validate(d.token, publicKeyRSA, JwtAlgorithm.allRSA) }
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, publicKeyRSA, JwtAlgorithm.allRSA) }
      }

      mock.tearDown
    }

    it("should invalidate WTF tokens") {
      val tokens = Seq("1", "abcde", "", "a.b.c.d")

      tokens.foreach { token =>
        intercept[JwtLengthException] { Jwt.validate(token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(false, token) { Jwt.isValid(token, secretKey, JwtAlgorithm.allHmac) }
      }
    }

    it("should invalidate non-base64 tokens") {
      val tokens = Seq("a.b", "a.b.c", "1.2.3", "abcde.azer.azer", "aze$.azer.azer")

      tokens.foreach { token =>
        intercept[IllegalArgumentException] { Jwt.validate(token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(false, token) { Jwt.isValid(token, secretKey, JwtAlgorithm.allHmac) }
      }
    }

    it("should invalidate expired tokens") {
      val mock = mockAfterExpiration

      data foreach { d =>
        intercept[JwtExpirationException] { Jwt.validate(d.token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, secretKey, JwtAlgorithm.allHmac) }
        intercept[JwtExpirationException] { Jwt.validate(d.token, secretKeyOf(d.alg)) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, secretKeyOf(d.alg)) }
      }

      dataRSA foreach { d =>
        intercept[JwtExpirationException] { Jwt.validate(d.token, publicKeyRSA, JwtAlgorithm.allRSA) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, publicKeyRSA, JwtAlgorithm.allRSA) }
      }

      mock.tearDown
    }

    it("should validate expired tokens with leeway") {
      val mock = mockAfterExpiration
      val options = JwtOptions(leeway = 60)

      data foreach { d =>
        Jwt.validate(d.token, secretKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, secretKey, JwtAlgorithm.allHmac, options) }
        Jwt.validate(d.token, secretKeyOf(d.alg), options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, secretKeyOf(d.alg), options) }
      }

      dataRSA foreach { d =>
        Jwt.validate(d.token, publicKeyRSA, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, publicKeyRSA, JwtAlgorithm.allRSA, options) }
      }

      mock.tearDown
    }

    it("should invalidate early tokens") {
      val mock = mockBeforeNotBefore

      data foreach { d =>
        val claimNotBefore = claimClass.copy(notBefore = Option(notBefore))
        val token = Jwt.encode(claimNotBefore, secretKey, d.alg)

        intercept[JwtNotBeforeException] { Jwt.validate(token, secretKey, JwtAlgorithm.allHmac) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(token, secretKey, JwtAlgorithm.allHmac) }
        intercept[JwtNotBeforeException] { Jwt.validate(token, secretKeyOf(d.alg)) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(token, secretKeyOf(d.alg)) }
      }

      dataRSA foreach { d =>
        val claimNotBefore = claimClass.copy(notBefore = Option(notBefore))
        val token = Jwt.encode(claimNotBefore, privateKeyRSA, d.alg)

        intercept[JwtNotBeforeException] { Jwt.validate(token, publicKeyRSA, JwtAlgorithm.allRSA) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(token, publicKeyRSA, JwtAlgorithm.allRSA) }
      }

      mock.tearDown
    }

    it("should validate early tokens with leeway") {
      val mock = mockBeforeNotBefore
      val options = JwtOptions(leeway = 60)

      data foreach { d =>
        val claimNotBefore = claimClass.copy(notBefore = Option(notBefore))
        val token = Jwt.encode(claimNotBefore, secretKey, d.alg)

        Jwt.validate(token, secretKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(token, secretKey, JwtAlgorithm.allHmac, options) }
        Jwt.validate(token, secretKeyOf(d.alg), options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(token, secretKeyOf(d.alg), options) }
      }

      dataRSA foreach { d =>
        val claimNotBefore = claimClass.copy(notBefore = Option(notBefore))
        val token = Jwt.encode(claimNotBefore, privateKeyRSA, d.alg)

        intercept[JwtNotBeforeException] { Jwt.validate(token, publicKeyRSA, JwtAlgorithm.allRSA) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(token, publicKeyRSA, JwtAlgorithm.allRSA) }
      }

      mock.tearDown
    }

    it("should invalidate wrong keys") {
      val mock = mockValidTime

      data foreach { d =>
        intercept[JwtValidationException] { Jwt.validate(d.token, "wrong key", JwtAlgorithm.allHmac) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, "wrong key", JwtAlgorithm.allHmac) }
      }

      dataRSA foreach { d =>
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, "wrong key", JwtAlgorithm.allRSA) }
      }

      mock.tearDown
    }

    it("should fail on non-exposed algorithms") {
      val mock = mockValidTime

      data foreach { d =>
        intercept[JwtValidationException] { Jwt.validate(d.token, secretKey, Seq.empty[JwtHmacAlgorithm]) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, secretKey, Seq.empty[JwtHmacAlgorithm]) }
      }

      data foreach { d =>
        intercept[JwtValidationException] { Jwt.validate(d.token, secretKey, JwtAlgorithm.allRSA) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, secretKey, JwtAlgorithm.allRSA) }
      }

      dataRSA foreach { d =>
        intercept[JwtValidationException] { Jwt.validate(d.token, publicKeyRSA, JwtAlgorithm.allHmac) }
        assertResult(false, d.alg.fullName) { Jwt.isValid(d.token, publicKeyRSA, JwtAlgorithm.allHmac) }
      }

      mock.tearDown
    }

    it("should invalidate wrong algos") {
      val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJXVEYifQ.e30"
      assert(Jwt.decode(token).isFailure)
      intercept[JwtNonSupportedAlgorithm] { Jwt.decode(token).get }
    }

    it("should skip expiration validation depending on options") {
      val mock = mockAfterExpiration
      val options = JwtOptions(expiration = false)

      data foreach { d =>
        Jwt.validate(d.token, secretKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, secretKey, JwtAlgorithm.allHmac, options) }
        Jwt.validate(d.token, secretKeyOf(d.alg), options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, secretKeyOf(d.alg), options) }
      }

      dataRSA foreach { d =>
        Jwt.validate(d.token, publicKeyRSA, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, publicKeyRSA, JwtAlgorithm.allRSA, options) }
      }

      mock.tearDown
    }

    it("should skip notBefore validation depending on options") {
      val mock = mockBeforeNotBefore
      val options = JwtOptions(notBefore = false)

      data foreach { d =>
        val claimNotBefore = claimClass.copy(notBefore = Option(notBefore))
        val token = Jwt.encode(claimNotBefore, secretKey, d.alg)

        Jwt.validate(token, secretKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(token, secretKey, JwtAlgorithm.allHmac, options) }
        Jwt.validate(token, secretKeyOf(d.alg), options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(token, secretKeyOf(d.alg), options) }
      }

      dataRSA foreach { d =>
        val claimNotBefore = claimClass.copy(notBefore = Option(notBefore))
        val token = Jwt.encode(claimNotBefore, privateKeyRSA, d.alg)

        Jwt.validate(token, publicKeyRSA, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(token, publicKeyRSA, JwtAlgorithm.allRSA, options) }
      }

      mock.tearDown
    }

    it("should skip signature validation depending on options") {
      val mock = mockValidTime
      val options = JwtOptions(signature = false)

      data foreach { d =>
        Jwt.validate(d.token, "wrong key", JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, "wrong key", JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        assertResult(true, d.alg.fullName) { Jwt.isValid(d.token, "wrong key", JwtAlgorithm.allRSA, options) }
      }

      mock.tearDown
    }
  }
}
