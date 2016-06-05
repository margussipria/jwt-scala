package eu.sipria.jwt
package json4s

package object jackson extends JwtJson4sImplicits {
  implicit val jwtJson = JwtJson4sJackson
  implicit val jwtTime = JwtTime
}
