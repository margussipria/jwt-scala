package eu.sipria

package object jwt {
  implicit val jwtTime: JwtTime = new JwtTime
}
