package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm

case class JwtHeader(
  alg: Option[JwtAlgorithm] = None,
  typ: Option[String] = None,
  cty: Option[String] = None
) extends JwtJson {
  /** Assign the type to the header */
  def withType(typ: String): JwtHeader = this.copy(typ = Option(typ))

  /** Assign the default type `JWT` to the header */
  def withType: JwtHeader = this.withType(JwtHeader.DEFAULT_TYPE)
}

object JwtHeader {
  val DEFAULT_TYPE = "JWT"

  def apply(alg: JwtAlgorithm): JwtHeader = new JwtHeader(Option(alg), Option(DEFAULT_TYPE))

  def apply(alg: JwtAlgorithm, typ: String): JwtHeader = new JwtHeader(Option(alg), Option(typ))

  def apply(alg: JwtAlgorithm, typ: String, cty: String): JwtHeader = new JwtHeader(Option(alg), Option(typ), Option(cty))
}
