package eu.sipria.jwt

case class JwtOptions(
  signature: Boolean = true,
  issuer: Option[String] = None,
  subject: Option[String] = None,
  audience: Option[String] = None,
  issuedAt: Option[Long] = None,
  jwtId: Option[String] = None,
  expiration: Boolean = true,
  notBefore: Boolean = true,
  leeway: Long = 0 // in seconds
)

object JwtOptions {
  val DEFAULT = JwtOptions()
}
