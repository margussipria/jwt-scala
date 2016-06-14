package eu.sipria.jwt
package json4s

package object native extends JwtJson4sImplicits {
  implicit val jwtJson = JwtJson4sNative
}
