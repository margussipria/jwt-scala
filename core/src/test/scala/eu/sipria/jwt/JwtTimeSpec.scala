package eu.sipria.jwt

import eu.sipria.jwt.exceptions.{JwtExpirationException, JwtNotBeforeException}

class JwtTimeSpec extends UnitSpec {

  describe("JwtTime") {

    it("should validate timestamp correctly") {

      val now = JwtTime.now

      val past = now - 10
      val future = now + 10

      JwtTime.isNowIsBetween(Some(past), Some(future)) should be (true)

      intercept[JwtExpirationException] {
        JwtTime.validateNowIsBetween(None, Some(past))
      }

      intercept[JwtNotBeforeException] {
        JwtTime.validateNowIsBetween(Some(future), None)
      }
    }
  }
}
