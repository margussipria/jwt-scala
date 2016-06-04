package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.exceptions.JwtNonStringException
import play.api.libs.json.{JsNull, JsObject, JsString, Json}

object JwtPlayJson extends JwtCore[JsObject] {
  def parse(value: String): JsObject = Json.parse(value).as[JsObject]
  def stringify(value: JsObject): String = Json.stringify(value)
  def getAlgorithm(header: JsObject): Option[JwtAlgorithm] = (header \ "alg").toOption.flatMap {
    case JsString(alg) => JwtAlgorithm.optionFromString(alg)
    case JsNull => None
    case _ => throw new JwtNonStringException("alg")
  }

  def getJson(jwtJson: JwtJson): JsObject = jwtJson match {
    case jwtJson: JwtHeader => jwtHeaderWriter.writes(jwtJson)
    case jwtJson: JwtClaim[JsObject] => jwtClaimWriter.writes(jwtJson)
  }

  def parseHeader(header: JsObject): JwtHeader = jwtHeaderReader.reads(header).get
  def parseClaim(claim: JsObject): JwtClaim[JsObject] = jwtClaimReader.reads(claim).get

  def parseHeader(header: String): JwtHeader = parseHeader(Json.parse(header).asInstanceOf[JsObject])
  def parseClaim(claim: String): JwtClaim[JsObject] = parseClaim(Json.parse(claim).asInstanceOf[JsObject])
}
