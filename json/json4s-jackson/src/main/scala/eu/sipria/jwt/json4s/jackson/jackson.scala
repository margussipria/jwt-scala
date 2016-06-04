package eu.sipria.jwt.json4s

import eu.sipria.jwt.JwtTime

package object jackson extends JwtJson4sImplicits {
  implicit val jwtJson = JwtJson4sJackson
  implicit val jwtTime = JwtTime
}
