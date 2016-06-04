package eu.sipria.jwt

import java.security.Key

import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtHmacAlgorithm}
import eu.sipria.jwt.exceptions.{JwtExpirationException, JwtNotBeforeException, JwtValidationException}

abstract class JwtJsonCommonSpec[J] extends UnitSpec with JsonCommonFixture[J] {
  implicit def jwtJson: JwtCore[J]

  def jwtPrivateKey(key: String, alg: JwtAlgorithm): Key = JwtUtils.getSigningKeyFromBase64(key, alg)

  def jwtPublicKey(key: String, alg: JwtAlgorithm): Key = JwtUtils.getVerifyKeyFromBase64(key, alg)

  def battleTestEncode(d: JsonDataEntryTrait[J], key: String) = {
    assertResult(d.token, d.alg.fullName + " key") { JwtToken(d.headerJson, claimJson, jwtPrivateKey(key, d.alg)).toString }
    assertResult(d.tokenEmpty, d.alg.fullName + " no key, no algorithm") { JwtToken(headerEmptyJson, claimJson).toString }
    assertResult(d.token, d.alg.fullName + " no header, key, algorithm") {
      JwtToken(
        jwtJson.parseClaim(jwtJson.stringify(claimJson)),
        jwtPrivateKey(key, d.alg),
        d.alg
      ).toString
    }

    assertResult(d.tokenEmpty, d.alg.fullName) { JwtToken(jwtJson.parse(headerEmpty), jwtJson.parse(claim)).toString }
    assertResult(d.token, d.alg.fullName) { JwtToken(
      jwtJson.parse(d.header),
      jwtJson.parse(claim),
      JwtUtils.getSigningKeyFromBase64(key, d.alg)
    ).toString }
    assertResult(d.tokenEmpty, d.alg.fullName) { JwtToken(headerClassEmpty, claimClass).toString }
    assertResult(d.token, d.alg.fullName) { JwtToken(d.headerClass, claimClass, JwtUtils.getSigningKeyFromBase64(key, d.alg)).toString }
  }

  describe("JwtJson") {
    it("should encode with no algorithm") {
      assertResult(tokenEmpty, "Unsigned key") { JwtToken(headerEmptyJson, claimJson).toString }
    }

    it("should encode HMAC") {
      dataJson foreach { d => battleTestEncode(d, secretKeyBase64) }
    }

    it("should encode RSA") {
      dataRSAJson foreach { d => battleTestEncode(d, privateKeyRSA) }
    }

    it("should decode") {
      implicit val jwtTime = mockValidTime
      data foreach { d =>
        val jwtToken = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64, d.signature)

        JwtToken(d.token) should be (jwtToken)

        jwtToken.isValid(secretKeyOf(d.alg), JwtAlgorithm.allHmac) should be (true)
      }
    }

    it("should be symmetric") {
      implicit val jwtTime = mockValidTime
      data foreach { d =>
        val token = JwtToken(
          jwtJson.parse(d.header),
          jwtJson.parse(claim),
          secretKeyOf(d.alg)
        ).toString
        val decoded = JwtToken(token)

        decoded.isValid(secretKeyOf(d.alg), JwtAlgorithm.allHmac, JwtOptions.DEFAULT) should be (true)

        decoded.header should be (d.headerClass)
        decoded.claim should be (claimClass)
        decoded.signature should be (d.signature)
      }

      dataRSA foreach { d =>
        val token = JwtToken(d.headerClass, claimClass, randomRSAKey.getPrivate).toString

        val jwtToken = JwtToken(token)

        assert(
          jwtToken.header === d.headerClass && jwtToken.claim === claimClass && jwtToken.isValid(randomRSAKey.getPublic, JwtAlgorithm.allRSA),
          d.alg.fullName
        )
      }

      dataECDSA foreach { d =>
        val token = JwtToken(d.headerClass, claimClass, randomECKey.getPrivate).toString

        val jwtToken = JwtToken(token)

        assert(
          jwtToken.header === d.headerClass && jwtToken.claim === claimClass && jwtToken.isValid(randomECKey.getPublic, JwtAlgorithm.allECDSA),
          d.alg.fullName
        )
      }
    }

    it("should validate") {
      implicit val jwtTime = mockValidTime

      dataJson foreach { d =>
        val success = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64,  d.signature)
        assertResult(success, d.alg.fullName) { JwtToken(d.token) }
        success.isValid(secretKeyOf(d.alg), JwtAlgorithm.allHmac, JwtOptions.DEFAULT) should be (true)
      }

      dataRSAJson foreach { d =>
        val success = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64,  d.signature)
        assertResult(success, d.alg.fullName) { JwtToken(d.token) }
        success.isValid(jwtPublicKey(publicKeyRSA, d.alg), JwtAlgorithm.allRSA, JwtOptions.DEFAULT) should be (true)
      }
    }

    it("should fail to validate when now is after expiration date") {
      implicit val jwtTime = mockAfterExpiration

      dataJson foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        intercept[JwtExpirationException] { jwtToken.validate(hmacKey, JwtAlgorithm.allHmac).get }
        assert(jwtToken.validate(hmacKey, JwtAlgorithm.allHmac).isFailure)
      }

      dataRSAJson foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        intercept[JwtExpirationException] { jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA).isFailure)
      }
    }

    it("should success to validate when now is after expiration date with options") {
      implicit val jwtTime = mockAfterExpiration
      val options = JwtOptions(expiration = false)

      dataJson foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        assert(jwtToken.validate(hmacKey, JwtAlgorithm.allHmac, options).isSuccess)
        jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac, options) should be (true)
      }

      dataRSAJson foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA, options).isSuccess)
        jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) should be (true)
      }
    }

    it("should invalidate expired tokens") {
      implicit val jwtTime = mockAfterExpiration

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        intercept[JwtExpirationException] { jwtToken.validate(hmacKey, JwtAlgorithm.allHmac).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        intercept[JwtExpirationException] { jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA) }
      }
    }

    it("should validate expired tokens with leeway") {
      implicit val jwtTime = mockAfterExpiration
      val options = JwtOptions(leeway = 60)

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        assert(jwtToken.validate(hmacKey, JwtAlgorithm.allHmac, options).isSuccess)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA, options).isSuccess)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) }
      }
    }

    it("should invalidate early tokens") {
      implicit val jwtTime = mockBeforeNotBefore

      data foreach { d =>
        val claimNotBefore = claimClass.copy(nbf = Option(notBefore))

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        val token = JwtToken(claimNotBefore, hmacKey, d.alg)

        intercept[JwtNotBeforeException] { token.validate(hmacKey, JwtAlgorithm.allHmac).get }
        assertResult(false, d.alg.fullName) { token.isValid(hmacKey, JwtAlgorithm.allHmac) }
      }

      dataRSA foreach { d =>
        val claimNotBefore = claimClass.copy(nbf = Option(notBefore))

        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        val token = JwtToken(claimNotBefore, rsaPrivateKey, d.alg)

        intercept[JwtNotBeforeException] { token.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assertResult(false, d.alg.fullName) { token.isValid(rsaPublicKey, JwtAlgorithm.allRSA) }
      }
    }

    it("should validate early tokens with leeway") {
      implicit val jwtTime = mockBeforeNotBefore
      val options = JwtOptions(leeway = 60)

      data foreach { d =>
        val claimNotBefore = claimClass.copy(nbf = Option(notBefore))

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        val token = JwtToken(claimNotBefore, hmacKey, d.alg)

        assert(token.validate(hmacKey, JwtAlgorithm.allHmac, options).isSuccess)
        assertResult(true, d.alg.fullName) { token.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val claimNotBefore = claimClass.copy(nbf = Option(notBefore))

        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        val token = JwtToken(claimNotBefore, rsaPrivateKey, d.alg)

        intercept[JwtNotBeforeException] { token.validate(rsaPublicKey, JwtAlgorithm.allRSA).get }
        assertResult(false, d.alg.fullName) { token.isValid(rsaPublicKey, JwtAlgorithm.allRSA) }
      }
    }
/*
    it("should invalidate wrong keys") {
      implicit val jwtTime = mockValidTime

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        intercept[JwtValidationException] { jwtToken.validate("wrong key", JwtAlgorithm.allHmac) }
        assertResult(false, d.alg.fullName) { jwtToken.isValid("wrong key", JwtAlgorithm.allHmac) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken(d.token)

        assertResult(false, d.alg.fullName) { jwtToken.isValid("wrong key", JwtAlgorithm.allRSA) }
      }
    }
*/
    it("should fail on non-exposed algorithms") {
      implicit val jwtTime = mockValidTime

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        intercept[JwtValidationException] { jwtToken.validate(hmacKey, Seq.empty[JwtHmacAlgorithm]).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(hmacKey, Seq.empty[JwtHmacAlgorithm]) }
      }

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        intercept[JwtValidationException] { jwtToken.validate(hmacKey, JwtAlgorithm.allRSA).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allRSA) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        intercept[JwtValidationException] { jwtToken.validate(rsaPublicKey, JwtAlgorithm.allHmac).get }
        assertResult(false, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allHmac) }
      }
    }

    it("should invalidate wrong algorithms") {
      val token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJXVEYifQ.e30"

      intercept[Exception] { JwtToken(token) } // TODO: Better exceptions for different json libraries
    }

    it("should skip expiration validation depending on options") {
      implicit val jwtTime = mockAfterExpiration
      val options = JwtOptions(expiration = false)

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        jwtToken.validate(hmacKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        jwtToken.validate(rsaPublicKey, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) }
      }
    }

    it("should skip notBefore validation depending on options") {
      implicit val jwtTime = mockBeforeNotBefore
      val options = JwtOptions(notBefore = false)

      data foreach { d =>
        val claimNotBefore = claimClass.copy(nbf = Option(notBefore))

        val hmacKey = jwtPublicKey(secretKeyBase64, d.alg)

        val token = JwtToken(claimNotBefore, hmacKey, d.alg)

        token.validate(hmacKey, JwtAlgorithm.allHmac, options)
        assertResult(true, d.alg.fullName) { token.isValid(hmacKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val claimNotBefore = claimClass.copy(nbf = Option(notBefore))

        val rsaPrivateKey = jwtPrivateKey(privateKeyRSA, d.alg)
        val rsaPublicKey = jwtPublicKey(publicKeyRSA, d.alg)

        val token = JwtToken(claimNotBefore, rsaPrivateKey, d.alg)

        token.validate(rsaPublicKey, JwtAlgorithm.allRSA, options)
        assertResult(true, d.alg.fullName) { token.isValid(rsaPublicKey, JwtAlgorithm.allRSA, options) }
      }
    }

    it("should skip signature validation depending on options") {
      implicit val jwtTime = mockValidTime
      val options = JwtOptions(signature = false)

      data foreach { d =>
        val jwtToken = JwtToken(d.token)

        val rsaPublicKey = jwtPublicKey(publicKeyRSA, JwtAlgorithm.RS256)

        assert(jwtToken.validate(rsaPublicKey, JwtAlgorithm.allHmac, options).isSuccess)
        assertResult(true, d.alg.fullName) { jwtToken.isValid(rsaPublicKey, JwtAlgorithm.allHmac, options) }
      }

      dataRSA foreach { d =>
        val jwtToken = JwtToken(d.token)

        val hmacKey = jwtPublicKey(secretKeyBase64, JwtAlgorithm.HS256)

        assertResult(true, d.alg.fullName) { jwtToken.isValid(hmacKey, JwtAlgorithm.allRSA, options) }
      }
    }
  }
}
