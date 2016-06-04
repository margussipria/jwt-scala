package eu.sipria.jwt

import io.circe._

class JwtCirceSpec extends JwtJsonCommonSpec[Json] with CirceFixture {
  val jwtJson = JwtCirce
}
