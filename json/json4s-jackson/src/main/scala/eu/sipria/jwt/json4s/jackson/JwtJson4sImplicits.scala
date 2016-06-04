package eu.sipria.jwt.json4s.jackson

import eu.sipria.jwt.{JwtClaim, JwtHeader}
import org.json4s.JValue

trait JwtJson4sImplicits {

  implicit class RichJwtHeader(header: JwtHeader) {
    def toJValue: JValue = JwtJson4sJackson.writeHeader(header)
  }

  implicit class RichJwtClaim(claim: JwtClaim[JValue]) extends eu.sipria.jwt.claim.RicJwtClaim(claim) {
    def toJValue: JValue = JwtJson4sJackson.writeClaim(claim)
  }
}
