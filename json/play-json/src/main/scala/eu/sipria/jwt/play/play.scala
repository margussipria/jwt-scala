package eu.sipria.jwt

package object play extends JwtJsonImplicits {
  implicit val jwtJson = JwtPlayJson
}