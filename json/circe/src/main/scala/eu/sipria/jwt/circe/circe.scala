package eu.sipria.jwt

package object circe {
  implicit val jwtJson = JwtCirce
  implicit val jwtTime = JwtTime
}
