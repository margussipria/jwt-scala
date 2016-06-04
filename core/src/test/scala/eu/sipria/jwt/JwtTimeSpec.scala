package eu.sipria.jwt

import eu.sipria.jwt.exceptions.{JwtExpirationException, JwtNotBeforeException}

class JwtTimeSpec extends UnitSpec {

  describe("JwtTime") {

    it("should validate timestamp correctly") {

      val time = new JwtTime
      val now = time.now

      val past = now - 10
      val future = now + 10

      time.isNowIsBetween(Some(past), Some(future)) should be (true)

      intercept[JwtExpirationException] {
        time.validateNowIsBetween(None, Some(past))
      }

      intercept[JwtNotBeforeException] {
        time.validateNowIsBetween(Some(future), None)
      }
    }
  }
}
