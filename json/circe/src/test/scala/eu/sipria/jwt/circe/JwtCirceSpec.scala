package eu.sipria.jwt.circe

import eu.sipria.jwt.JwtJsonCommonSpec
import io.circe._

class JwtCirceSpec extends JwtJsonCommonSpec[Json] with CirceFixture {
  val jwtJson = JwtCirce
}
