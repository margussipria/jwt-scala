package eu.sipria.jwt
package play

import _root_.play.api.libs.json.{JsNull, JsObject, JsString, Json}
import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.exceptions.JwtNonStringException

object JwtPlayJson extends JwtCore[JsObject] {
  def parse(value: String): JsObject = Json.parse(value).as[JsObject]
  def stringify(value: JsObject): String = Json.stringify(value)
  def getAlgorithm(header: JsObject): Option[JwtAlgorithm] = (header \ "alg").toOption.flatMap {
    case JsString(alg) => JwtAlgorithm.optionFromString(alg)
    case JsNull => None
    case _ => throw new JwtNonStringException("alg")
  }

  def writeHeader(header: JwtHeader): JsObject = jwtHeaderWriter.writes(header)
  def writeClaim(claim: JwtClaim[JsObject]): JsObject = jwtClaimWriter.writes(claim)

  def parseHeader(header: JsObject): JwtHeader = jwtHeaderReader.reads(header).get
  def parseClaim(claim: JsObject): JwtClaim[JsObject] = jwtClaimReader.reads(claim).get

  def parseHeader(header: String): JwtHeader = parseHeader(Json.parse(header).asInstanceOf[JsObject])
  def parseClaim(claim: String): JwtClaim[JsObject] = parseClaim(Json.parse(claim).asInstanceOf[JsObject])
}
