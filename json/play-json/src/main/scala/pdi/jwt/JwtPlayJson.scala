package pdi.jwt

import pdi.jwt.exceptions.JwtNonStringException
import play.api.libs.json._

/**
  * Implementation of `JwtCore` using `JsObject` from Play JSON.
  *
  * To see a full list of samples, check the [[http://pauldijou.fr/jwt-scala/samples/jwt-play-json/ online documentation]].
  */
object JwtPlayJson extends JwtJsonCommon[JsObject] {
  protected def parse(value: String): JsObject = Json.parse(value).as[JsObject]

  protected def stringify(value: JsObject): String = Json.stringify(value)

  protected def getAlgorithm(header: JsObject): Option[JwtAlgorithm] = (header \ "alg").toOption.flatMap {
    case JsString("none") => None
    case JsString(alg) => Option(JwtAlgorithm.fromString(alg))
    case JsNull => None
    case _ => throw new JwtNonStringException("alg")
  }

  protected def parseHeader(header: String): JwtHeader = jwtHeaderReader.reads(Json.parse(header)).get
  protected def parseClaim(claim: String): JwtClaim = jwtClaimReader.reads(Json.parse(claim)).get
}
