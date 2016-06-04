package eu.sipria.jwt

package object claim {

  implicit class RicJwtClaim(claim: JwtClaim) {

    def by(issuer: String): JwtClaim = claim.copy(iss = Option(issuer))
    def to(audience: String): JwtClaim = claim.copy(aud = Option(audience))
    def about(subject: String): JwtClaim = claim.copy(sub = Option(subject))
    def withId(id: String): JwtClaim = claim.copy(jti = Option(id))

    def expiresIn(seconds: Long)(implicit jwtTime: JwtTime): JwtClaim = claim.copy(exp = Option(jwtTime.now + seconds))
    def expiresAt(seconds: Long): JwtClaim = claim.copy(exp = Option(seconds))
    def expiresNow(implicit jwtTime: JwtTime): JwtClaim = claim.copy(exp = Option(jwtTime.now))

    def startsIn(seconds: Long)(implicit jwtTime: JwtTime): JwtClaim = claim.copy(nbf = Option(jwtTime.now + seconds))
    def startsAt(seconds: Long): JwtClaim = claim.copy(nbf = Option(seconds))
    def startsNow(implicit jwtTime: JwtTime): JwtClaim = claim.copy(nbf = Option(jwtTime.now))

    def issuedIn(seconds: Long)(implicit jwtTime: JwtTime): JwtClaim = claim.copy(iat = Option(jwtTime.now + seconds))
    def issuedAt(seconds: Long): JwtClaim = claim.copy(iat = Option(seconds))
    def issuedNow(implicit jwtTime: JwtTime): JwtClaim = claim.copy(iat = Option(jwtTime.now))

    def isValid(implicit jwtTime: JwtTime): Boolean = jwtTime.isNowIsBetween(claim.nbf, claim.exp)
    def isValid(issuer: String)(implicit jwtTime: JwtTime): Boolean = claim.iss.contains(issuer) && isValid
    def isValid(issuer: String, audience: String)(implicit jwtTime: JwtTime): Boolean = claim.aud.contains(audience) && isValid(issuer)
  }
}
