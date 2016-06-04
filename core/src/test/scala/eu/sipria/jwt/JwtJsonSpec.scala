package eu.sipria.jwt

import eu.sipria.jwt.claim._

class JwtJsonSpec extends UnitSpec {

  describe("JwtJson") {
    it("should implicitly construct claim") {

      assertResult(JwtClaim(
        iss = Some("me"),
        aud = Some("you"),
        sub = Some("something"),
        exp = Some(15),
        nbf = Some(10),
        iat = Some(10)
      ), "Claim") {
        JwtClaim().by("me").to("you").about("something").issuedAt(10).startsAt(10).expiresAt(15)
      }
    }
  }
}
