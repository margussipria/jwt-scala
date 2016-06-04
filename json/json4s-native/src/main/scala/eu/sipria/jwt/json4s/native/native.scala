package eu.sipria.jwt.json4s

import eu.sipria.jwt.JwtTime

package object native extends JwtJson4sImplicits {
  implicit val jwtJson = JwtJson4sNative
  implicit val jwtTime = JwtTime
}
