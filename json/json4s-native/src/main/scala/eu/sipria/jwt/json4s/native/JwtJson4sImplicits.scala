package eu.sipria.jwt
package json4s
package native

import org.json4s.JValue

trait JwtJson4sImplicits {

  implicit class RichJwtHeader(header: JwtHeader) {
    def toJValue: JValue = JwtJson4sNative.writeHeader(header)
  }

  implicit class RichJwtClaim(claim: JwtClaim[JValue]) extends eu.sipria.jwt.claim.RicJwtClaim(claim) {
    def toJValue: JValue = JwtJson4sNative.writeClaim(claim)
  }
}
