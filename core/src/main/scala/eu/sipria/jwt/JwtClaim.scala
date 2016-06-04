package eu.sipria.jwt

case class JwtClaim[JsonType](
  content: JsonType,
  // issuer
  iss: Option[String] = None,
  // subject
  sub: Option[String] = None,
  // audience
  aud: Option[String] = None,
  // expiration
  exp: Option[Long] = None,
  // not before
  nbf: Option[Long] = None,
  // issued at
  iat: Option[Long] = None,
  // jwt id
  jti: Option[String] = None
) extends JwtJson
