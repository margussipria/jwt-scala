package eu.sipria.jwt.json4s.native

import eu.sipria.jwt.{JwtClaim, JwtHeader}
import org.json4s.JValue

trait JwtJson4sImplicits {

  implicit class RichJwtHeader(header: JwtHeader) {
    def toJValue: JValue = JwtJson4sNative.writeHeader(header)
  }

  implicit class RichJwtClaim(claim: JwtClaim[JValue]) extends eu.sipria.jwt.claim.RicJwtClaim(claim) {
    def toJValue: JValue = JwtJson4sNative.writeClaim(claim)
  }
}
