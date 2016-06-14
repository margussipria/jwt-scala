package eu.sipria.jwt

import java.security.Key

import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtHmacAlgorithm}
import eu.sipria.jwt.exceptions.{JwtExpirationException, JwtNotBeforeException, JwtValidationException}

abstract class JwtJsonCommonSpec[J] extends UnitSpec with JsonCommonFixture[J] {
  implicit def jwtJson: JwtCore[J]

  def jwtPrivateKey(key: String, alg: JwtAlgorithm): Key = JwtUtils.getSigningKeyFromBase64(key, alg)

  def jwtPublicKey(key: String, alg: JwtAlgorithm): Key = JwtUtils.getVerifyKeyFromBase64(key, alg)

  def battleTestEncode(d: JsonDataEntryTrait[J], key: String) = {
    assertResult(d.token, d.alg.fullName + " key") { JwtToken.encode(d.headerJson, claimJson, jwtPrivateKey(key, d.alg)).toString }
    assertResult(d.tokenEmpty, d.alg.fullName + " no key, no algorithm") { JwtToken.encode(headerEmptyJson, claimJson).toString }
    assertResult(d.token, d.alg.fullName + " no header, key, algorithm") {
      JwtToken.encode(
        jwtJson.parseClaim(jwtJson.stringify(claimJson)),
        jwtPrivateKey(key, d.alg),
        d.alg
      ).toString
    }

    assertResult(d.tokenEmpty, d.alg.fullName) { JwtToken.encode(jwtJson.parse(headerEmpty), jwtJson.parse(claim)).toString }
    assertResult(d.token, d.alg.fullName) { JwtToken.encode(
      jwtJson.parse(d.header),
      jwtJson.parse(claim),
      JwtUtils.getSigningKeyFromBase64(key, d.alg)
    ).toString }
    assertResult(d.tokenEmpty, d.alg.fullName) { JwtToken.encode(headerClassEmpty, claimClass).toString }
    assertResult(d.token, d.alg.fullName) { JwtToken.encode(d.headerClass, claimClass, JwtUtils.getSigningKeyFromBase64(key, d.alg)).toString }
  }

  val jwtOptions = JwtOptions(expiration = false, notBefore = false)

  describe("JwtJson") {
    it("should encode with no algorithm") {
      assertResult(tokenEmpty, "Unsigned key") { JwtToken.encode(headerEmptyJson, claimJson).toString }
    }

    it("should encode HMAC") {
      dataJson foreach { d => battleTestEncode(d, secretKeyBase64) }
    }

    it("should encode RSA") {
      dataRSAJson foreach { d => battleTestEncode(d, privateKeyRSA) }
    }

    it("should decode") {
      data foreach { d =>
        val jwtToken = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64, d.signature)

        JwtToken.decode(d.token) should be (jwtToken)

        jwtToken.isValid(secretKeyOf(d.alg), JwtAlgorithm.allHmac, jwtOptions) should be (true)
      }
    }

    it("should be symmetric") {
      data foreach { d =>
        val token = JwtToken.encode(
          jwtJson.parse(d.header),
          jwtJson.parse(claim),
          secretKeyOf(d.alg)
        ).toString
        val decoded = JwtToken.decode(token)

        decoded.isValid(secretKeyOf(d.alg), JwtAlgorithm.allHmac, jwtOptions) should be (true)

        decoded.header should be (d.headerClass)
        decoded.claim should be (claimClass)
        decoded.signature should be (d.signature)
      }

      dataRSA foreach { d =>
        val token = JwtToken.encode(d.headerClass, claimClass, randomRSAKey.getPrivate).toString

        val jwtToken = JwtToken.decode(token)

        assert(
          jwtToken.header === d.headerClass && jwtToken.claim === claimClass && jwtToken.isValid(randomRSAKey.getPublic, JwtAlgorithm.allRSA, jwtOptions),
          d.alg.fullName
        )
      }

      dataECDSA foreach { d =>
        val token = JwtToken.encode(d.headerClass, claimClass, randomECKey.getPrivate).toString

        val jwtToken = JwtToken.decode(token)

        assert(
          jwtToken.header === d.headerClass && jwtToken.claim === claimClass && jwtToken.isValid(randomECKey.getPublic, JwtAlgorithm.allECDSA, jwtOptions),
          d.alg.fullName
        )
      }
    }

    it("should validate") {
      dataJson foreach { d =>
        val success = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64,  d.signature)
        assertResult(success, d.alg.fullName) { JwtToken.decode(d.token) }
        success.isValid(secretKeyOf(d.alg), JwtAlgorithm.allHmac, jwtOptions) should be (true)
      }

      dataRSAJson foreach { d =>
        val success = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64,  d.signature)
        assertResult(success, d.alg.fullName) { JwtToken.decode(d.token) }
        success.isValid(jwtPublicKey(publicKeyRSA, d.alg), JwtAlgorithm.allRSA, jwtOptions) should be (true)
      }
    }

    it("should fail to validate when now is after expiration date") {
      val testExpiration = claimClass.copy(nbf = None, exp = Option(JwtTime.now - 30))

      dataJson foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)
        val jwtToken = JwtToken.encode(testExpiration, hmacKey, d.alg)

        intercept[JwtExpirationException] { jwtToken.validate(hmacKey, JwtAlgorithm.allHmac).get }
        assert(jwtToken.validate(hmacKey, JwtAlgorithm.allHmac).isFailure)
      }

      dataRSAJson foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)
        val jwtToken = JwtToken.encode(testExpiration, rsaPrivateKey, d.alg)

        intercept[JwtExpirationException] { jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA).isFailure)
      }
    }

    it("should success to validate when now is after expiration date with options") {
      val testExpiration = claimClass.copy(nbf = None, exp = Option(JwtTime.now - 30))
      val options = JwtOptions(expiration = false)

      dataJson foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)
        val jwtToken = JwtToken.encode(testExpiration, hmacKey, d.alg)

        assert(jwtToken.validate(hmacKey, JwtAlgorithm.allHmac, options).isSuccess)
        jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac, options) should be (true)
      }

      dataRSAJson foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)
        val jwtToken = JwtToken.encode(testExpiration, rsaPrivateKey, d.alg)

        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA, options).isSuccess)
        jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) should be (true)
      }
    }

    it("should validate expired tokens with leeway") {
      val testExpiration = claimClass.copy(nbf = None, exp = Option(JwtTime.now - 30))
      val options = JwtOptions(leeway = 60)

      data foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)
        val jwtToken = JwtToken.encode(testExpiration, hmacKey, d.alg)

        assert(jwtToken.validate(hmacKey, JwtAlgorithm.allHmac, options).isSuccess)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)
        val jwtToken = JwtToken.encode(testExpiration, rsaPrivateKey, d.alg)

        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA, options).isSuccess)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) }
      }
    }

    it("should invalidate early tokens") {
      val claimNotBefore = claimClass.copy(nbf = Option(JwtTime.now + 30), exp = None)

      data foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        val token = JwtToken.encode(claimNotBefore, hmacKey, d.alg)

        intercept[JwtNotBeforeException] { token.validate(hmacKey, JwtAlgorithm.allHmac).get }
        assertResult(false, d.alg.fullName) { token.isValid(hmacKey, JwtAlgorithm.allHmac) }
      }

      dataRSA foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        val token = JwtToken.encode(claimNotBefore, rsaPrivateKey, d.alg)

        intercept[JwtNotBeforeException] { token.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assertResult(false, d.alg.fullName) { token.isValid(rsaPublicKey, JwtAlgorithm.allRSA) }
      }
    }

    it("should validate early tokens with leeway") {
      val claimNotBefore = claimClass.copy(nbf = Option(JwtTime.now + 30), exp = None)
      val options = JwtOptions(leeway = 60)

      data foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        val token = JwtToken.encode(claimNotBefore, hmacKey, d.alg)

        assert(token.validate(hmacKey, JwtAlgorithm.allHmac, options).isSuccess)
        assertResult(true, d.alg.fullName) { token.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        val token = JwtToken.encode(claimNotBefore, rsaPrivateKey, d.alg)

        intercept[JwtNotBeforeException] { token.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assertResult(false, d.alg.fullName) { token.isValid(rsaPublicKey, JwtAlgorithm.allRSA) }
      }
    }

    it("should fail on non-exposed algorithms") {
      data foreach { d =>
        val jwtToken = JwtToken.decode(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        intercept[JwtValidationException] { jwtToken.validate(hmacKey, Seq.empty[JwtHmacAlgorithm], jwtOptions).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(hmacKey, Seq.empty[JwtHmacAlgorithm], jwtOptions) }
      }

      data foreach { d =>
        val jwtToken = JwtToken.decode(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        intercept[JwtValidationException] { jwtToken.validate(hmacKey, JwtAlgorithm.allRSA, jwtOptions).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allRSA, jwtOptions) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken.decode(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        intercept[JwtValidationException] { jwtToken.validate(rsaPublicKey, JwtAlgorithm.allHmac, jwtOptions).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allHmac, jwtOptions) }
      }
    }

    it("should invalidate wrong algorithms") {
      val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJXVEYifQ.e30"

      intercept[Exception] { JwtToken.decode(token) } // TODO: Better exceptions for different json libraries
    }

    it("should skip expiration validation depending on options") {
      val options = JwtOptions(expiration = false)

      val claimExpiration = claimClass.copy(nbf = None, exp = Option(JwtTime.now - 30))
      data foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)
        val jwtToken = JwtToken.encode(claimExpiration, hmacKey, d.alg)

        jwtToken.validate(hmacKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)
        val jwtToken = JwtToken.encode(claimExpiration, rsaPrivateKey, d.alg)

        jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) }
      }
    }

    it("should skip notBefore validation depending on options") {
      val options = JwtOptions(notBefore = false)

      val claimNotBefore = claimClass.copy(nbf = Option(JwtTime.now + 30), exp = None)
      data foreach { d =>
        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        val token = JwtToken.encode(claimNotBefore, hmacKey, d.alg)

        token.validate(hmacKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { token.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        val token = JwtToken.encode(claimNotBefore, rsaPrivateKey, d.alg)

        token.validate(rsaPublicKey, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { token.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) }
      }
    }

    it("should skip signature validation depending on options") {
      val options = JwtOptions(signature = false, expiration = false, notBefore = false)

      data foreach { d =>
        val jwtToken = JwtToken.decode(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, JwtAlgorithm.RS256)

        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allHmac, options).isSuccess)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken.decode(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, JwtAlgorithm.HS256)

        assertResult(true, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allRSA, options) }
      }
    }
  }
}
