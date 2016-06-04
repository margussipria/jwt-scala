package eu.sipria.jwt.json4s.jackson

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.{JwtClaim, JwtHeader, JwtJsonCommonSpec}
import org.json4s.JsonDSL._
import org.json4s._

class JwtJson4sJacksonSpec extends JwtJsonCommonSpec[JValue] with Json4sJacksonFixture {
  val jwtJson = JwtJson4sJackson

  describe("JwtJson") {
    it("should implicitly convert to JValue") {
      assertResult((
        ("iss" -> "me") ~
        ("aud" -> "you") ~
        ("sub" -> "something") ~
        ("exp" -> 15) ~
        ("nbf" -> 10) ~
        ("iat" -> 10)
      ), "Claim") {
        JwtClaim(content = JObject.apply().asInstanceOf[JValue]).by("me").to("you").about("something").issuedAt(10).startsAt(10).expiresAt(15).toJValue
      }

      assertResult((
        ("typ" -> "JWT") ~
        ("alg" -> "HS256")
      ), "Claim") {
        JwtHeader(JwtAlgorithm.HS256).toJValue
      }
    }
  }
}
