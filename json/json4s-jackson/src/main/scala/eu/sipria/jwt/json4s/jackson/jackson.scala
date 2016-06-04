package eu.sipria.jwt.json4s

package object jackson extends JwtJson4sImplicits {
  implicit val jwtJson = JwtJson4sJackson
}
