package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm

trait JwtCore[JsonType] {
  def parse(json: String): JsonType
  def stringify(json: JsonType): String
  def getAlgorithm(header: JsonType): Option[JwtAlgorithm]

  def getJson(jwtJson: JwtJson): JsonType

  def parseHeader(header: JsonType): JwtHeader
  def parseClaim(claim: JsonType): JwtClaim

  def parseHeader(header: String): JwtHeader
  def parseClaim(claim: String): JwtClaim
}
