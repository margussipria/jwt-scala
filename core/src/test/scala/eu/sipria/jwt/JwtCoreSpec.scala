package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.algorithms.JwtAlgorithm.HmacSHA256
import eu.sipria.jwt.exceptions.JwtLengthException

class JwtCoreSpec extends UnitSpec with Fixture {

  implicit val jwtCore = new JwtCore[String] {
    def parse(json: String): String = ???
    def stringify(json: String): String = ???
    def getAlgorithm(header: String): Option[JwtAlgorithm] = ???

    def writeHeader(header: JwtHeader): String = ???
    def writeClaim(claim: JwtClaim[String]): String = ???

    def parseHeader(header: String): JwtHeader = ???
    def parseClaim(claim: String): JwtClaim[String] = ???
  }

  val jwtOptions = JwtOptions(expiration = false, notBefore = false)

  describe("JwtCore") {
    it("should validate correct tokens") {
      data foreach { d =>
        assertResult(true, d.alg.fullName) {
          val token = JwtToken(d.headerClass, claimClassString, d.header64 + "." + claim64, d.signature)

          token.isValid(JwtUtils.getVerifyKeyFromBase64(secretKeyBase64, d.alg), JwtAlgorithm.allHmac, jwtOptions)
        }
      }

      dataRSA foreach { d =>
        assertResult(true, d.alg.fullName) {
          val token = JwtToken(d.headerClass, claimClassString, d.header64 + "." + claim64, d.signature)

          token.isValid(JwtUtils.getVerifyKeyFromBase64(publicKeyRSA, d.alg), JwtAlgorithm.allRSA, jwtOptions)
        }
      }
    }

    it("should invalidate WTF tokens") {
      val tokens = Seq("1", "abcde", "", "a.b.c.d")

      tokens.foreach { token =>
        intercept[JwtLengthException] { JwtToken.decode(token) }
      }
    }

    it("should invalidate non-base64 tokens") {
      val tokens = Seq("a.b", "a.b.c", "1.2.3", "abcde.azer.azer", "aze$.azer.azer")

      tokens.foreach { token =>
        intercept[IllegalArgumentException] {
          JwtToken.decode(token).isValid(JwtUtils.getVerifyKeyFromBase64(secretKeyBase64, HmacSHA256), JwtAlgorithm.allHmac, jwtOptions)
        }
      }
    }
  }
}
