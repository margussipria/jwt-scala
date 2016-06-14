package eu.sipria.jwt

package object claim {

  implicit class RicJwtClaim[JsonType](claim: JwtClaim[JsonType]) {

    def by(issuer: String): JwtClaim[JsonType] = claim.copy(iss = Option(issuer))
    def to(audience: String): JwtClaim[JsonType] = claim.copy(aud = Option(audience))
    def about(subject: String): JwtClaim[JsonType] = claim.copy(sub = Option(subject))
    def withId(id: String): JwtClaim[JsonType] = claim.copy(jti = Option(id))

    def expiresIn(seconds: Long): JwtClaim[JsonType] = claim.copy(exp = Option(JwtTime.now + seconds))
    def expiresAt(seconds: Long): JwtClaim[JsonType] = claim.copy(exp = Option(seconds))
    def expiresNow: JwtClaim[JsonType] = claim.copy(exp = Option(JwtTime.now))

    def startsIn(seconds: Long): JwtClaim[JsonType] = claim.copy(nbf = Option(JwtTime.now + seconds))
    def startsAt(seconds: Long): JwtClaim[JsonType] = claim.copy(nbf = Option(seconds))
    def startsNow: JwtClaim[JsonType] = claim.copy(nbf = Option(JwtTime.now))

    def issuedIn(seconds: Long): JwtClaim[JsonType] = claim.copy(iat = Option(JwtTime.now + seconds))
    def issuedAt(seconds: Long): JwtClaim[JsonType] = claim.copy(iat = Option(seconds))
    def issuedNow: JwtClaim[JsonType] = claim.copy(iat = Option(JwtTime.now))

    def isValid: Boolean = JwtTime.isNowIsBetween(claim.nbf, claim.exp)
    def isValid(issuer: String): Boolean = claim.iss.contains(issuer) && isValid
    def isValid(issuer: String, audience: String): Boolean = claim.aud.contains(audience) && isValid(issuer)
  }
}
