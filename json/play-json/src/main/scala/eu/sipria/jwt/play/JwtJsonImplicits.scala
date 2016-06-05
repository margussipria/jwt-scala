package eu.sipria.jwt
package play

import _root_.play.api.libs.json._
import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.exceptions.{JwtNonNumberException, JwtNonStringException, JwtNonSupportedAlgorithm}

trait JwtJsonImplicits {
  private def extractString(json: JsObject, fieldName: String): Option[String] = (json \ fieldName).toOption.flatMap {
    case JsString(value) => Option(value)
    case JsNull => None
    case _ => throw new JwtNonStringException(fieldName)
  }

  private def extractLong(json: JsObject, fieldName: String): Option[Long] = (json \ fieldName).toOption.flatMap {
    case JsNumber(value) => Option(value.toLong)
    case JsNull => None
    case _ => throw new JwtNonNumberException(fieldName)
  }

  private def keyToPath(key: String): JsPath = new JsPath(List(new KeyPathNode(key)))

  implicit val jwtHeaderReader = new Reads[JwtHeader] {
    def reads(json: JsValue): JsResult[JwtHeader] = json match {
      case value: JsObject =>
        try {
          JsSuccess(JwtHeader.apply(
            alg = extractString(value, "alg").flatMap(JwtAlgorithm.optionFromString),
            typ = extractString(value, "typ"),
            cty = extractString(value, "cty")
          ))
        } catch {
          case e : JwtNonStringException => JsError(keyToPath(e.getKey), "error.expected.string")
          case e : JwtNonSupportedAlgorithm => JsError(keyToPath("alg"), "error.expected.algorithm")
        }
      case _ => JsError("error.expected.jsobject")
    }
  }

  implicit val jwtHeaderWriter = new Writes[JwtHeader] {
    def writes(header: JwtHeader): JsObject = {
      JsObject(Seq(
        header.typ
          .map(JsString).map("typ" -> _),
        header.alg.map(_.name).orElse(Option("none"))
          .map(JsString).map("alg" -> _),
        header.cty
          .map(JsString).map("cty" -> _)
      ).flatten)
    }
  }

  implicit val jwtClaimReader = new Reads[JwtClaim[JsObject]] {
    def reads(json: JsValue): JsResult[JwtClaim[JsObject]] = json match {
      case value: JsObject =>
        try {
          JsSuccess(
            JwtClaim.apply(
              content = value - "iss" - "sub" - "aud" - "exp" - "nbf" - "iat" - "jti",
              iss = extractString(value, "iss"),
              sub = extractString(value, "sub"),
              aud = extractString(value, "aud"),
              exp = extractLong(value, "exp"),
              nbf = extractLong(value, "nbf"),
              iat = extractLong(value, "iat"),
              jti = extractString(value, "jti")
            )
          )
        } catch {
          case e : JwtNonStringException => JsError(keyToPath(e.getKey), "error.expected.string")
          case e : JwtNonNumberException => JsError(keyToPath(e.getKey), "error.expected.number")
        }
      case _ => JsError("error.expected.jsobject")
    }
  }

  implicit val jwtClaimWriter = new Writes[JwtClaim[JsObject]] {
    def writes(claim: JwtClaim[JsObject]): JsObject = {
      val value = JsObject(Seq(
        claim.iss.map(JsString).map("iss" -> _),
        claim.sub.map(JsString).map("sub" -> _),
        claim.aud.map(JsString).map("aud" -> _),
        claim.exp.map(BigDecimal.apply).map(JsNumber).map("exp" -> _),
        claim.nbf.map(BigDecimal.apply).map(JsNumber).map("nbf" -> _),
        claim.iat.map(BigDecimal.apply).map(JsNumber).map("iat" -> _),
        claim.jti.map(JsString).map("jti" -> _)
      ).flatten)

      value ++ claim.content.asInstanceOf[JsObject]
    }
  }

  implicit class RichJwtHeader(header: JwtHeader) {
    def toJsValue: JsValue = jwtHeaderWriter.writes(header)
  }

  implicit class RichJwtClaim(claim: JwtClaim[JsObject]) extends eu.sipria.jwt.claim.RicJwtClaim(claim) {
    def toJsValue: JsValue = jwtClaimWriter.writes(claim)
  }
}
