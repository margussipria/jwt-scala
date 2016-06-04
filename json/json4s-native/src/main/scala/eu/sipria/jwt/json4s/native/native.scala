package eu.sipria.jwt.json4s

package object native extends JwtJson4sImplicits {
  implicit val jwtJson = JwtJson4sNative
}
