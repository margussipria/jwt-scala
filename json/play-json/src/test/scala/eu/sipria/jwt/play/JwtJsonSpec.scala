package eu.sipria.jwt.play

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.{JwtClaim, JwtHeader, JwtJsonCommonSpec}
import play.api.libs.json.{JsObject, Json}

class JwtJsonSpec extends JwtJsonCommonSpec[JsObject] with JsonFixture {
  val jwtJson = JwtPlayJson

  describe("JwtJson") {
    it("should implicitly convert to JsValue") {

      assertResult(Json.obj(
        "iss" -> "me",
        "aud" -> "you",
        "sub" -> "something",
        "exp" -> 15,
        "nbf" -> 10,
        "iat" -> 10
      ), "Claim") {
        JwtClaim(content = JsObject.apply(Seq.empty)).by("me").to("you").about("something").issuedAt(10).startsAt(10).expiresAt(15).toJsValue
      }

      assertResult(Json.obj(
        "typ" -> JwtHeader.DEFAULT_TYPE,
        "alg" -> JwtAlgorithm.HS256.name
      ), "Claim") {
        JwtHeader(JwtAlgorithm.HS256).toJsValue
      }
    }
  }
}
