package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm

class JwtHeaderSpec extends UnitSpec with Fixture {

  describe("JwtHeader") {

    it("should create JwtHeader correctly") {

      JwtHeader().withType should be (JwtHeader(typ = Some(JwtHeader.DEFAULT_TYPE)))

      JwtHeader().withType(JwtHeader.DEFAULT_TYPE) should be (JwtHeader(typ = Some(JwtHeader.DEFAULT_TYPE)))

      JwtHeader(JwtAlgorithm.HS256) should be (JwtHeader(
        Option(JwtAlgorithm.HS256),
        Option(JwtHeader.DEFAULT_TYPE),
        None
      ))

      JwtHeader(JwtAlgorithm.HS256, JwtHeader.DEFAULT_TYPE) should be (JwtHeader(
        Option(JwtAlgorithm.HS256),
        Option(JwtHeader.DEFAULT_TYPE),
        None
      ))

      JwtHeader(JwtAlgorithm.HS256, JwtHeader.DEFAULT_TYPE, "JWT") should be (JwtHeader(
        Option(JwtAlgorithm.HS256),
        Option(JwtHeader.DEFAULT_TYPE),
        Option("JWT")
      ))
    }
  }
}
