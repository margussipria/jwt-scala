package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.algorithms.JwtAlgorithm.HmacSHA256
import eu.sipria.jwt.exceptions.JwtLengthException

class JwtCoreSpec extends UnitSpec with Fixture {

  implicit val jwtTime = new JwtTime

  implicit val jwtCore = new JwtCore[String] {
    override def parse(json: String): String = ???

    override def stringify(json: String): String = ???

    override def getAlgorithm(header: String): Option[JwtAlgorithm] = ???

    override def getJson(jwtJson: JwtJson): String = ???

    override def parseHeader(header: String): JwtHeader = ???

    override def parseClaim(claim: String): JwtClaim = ???
  }

  describe("JwtCore") {
    it("should validate correct tokens") {
      implicit val jwtTime = mockValidTime

      data foreach { d =>
        assertResult(true, d.alg.fullName) {
          val token = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64, d.signature)

          token.isValid(JwtUtils.getVerifyKeyFromBase64(secretKeyBase64, d.alg), JwtAlgorithm.allHmac)
        }
      }

      dataRSA foreach { d =>
        assertResult(true, d.alg.fullName) {
          val token = JwtToken(d.headerClass, claimClass, d.header64 + "." + claim64, d.signature)

          token.isValid(JwtUtils.getVerifyKeyFromBase64(publicKeyRSA, d.alg), JwtAlgorithm.allRSA)
        }
      }
    }

    it("should invalidate WTF tokens") {
      val tokens = Seq("1", "abcde", "", "a.b.c.d")

      tokens.foreach { token =>
        intercept[JwtLengthException] { JwtToken(token) }
      }
    }

    it("should invalidate non-base64 tokens") {
      val tokens = Seq("a.b", "a.b.c", "1.2.3", "abcde.azer.azer", "aze$.azer.azer")

      tokens.foreach { token =>
        intercept[IllegalArgumentException] {
          JwtToken(token).isValid(JwtUtils.getVerifyKeyFromBase64(secretKeyBase64, HmacSHA256), JwtAlgorithm.allHmac)
        }
      }
    }
  }
}
