package eu.sipria.jwt
package json4s

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.exceptions.{JwtNonNumberException, JwtNonStringException}
import org.json4s.JsonAST.{JField, JInt, JObject, JString}
import org.json4s.JsonDSL._
import org.json4s._

trait JwtJson4sCommon extends JwtCore[JValue] {
  def getAlgorithm(header: JValue): Option[JwtAlgorithm] = header \ "alg" match {
    case JString(alg) => JwtAlgorithm.optionFromString(alg)
    case JNull | JNothing => None
    case _ => throw new JwtNonStringException("alg")
  }

  def readClaim(json: JValue): JwtClaim[JValue] = json match {
    case value: JObject => JwtClaim.apply(
      iss = extractString(value, "iss"),
      sub = extractString(value, "sub"),
      aud = extractString(value, "aud"),
      exp = extractLong(value, "exp"),
      nbf = extractLong(value, "nbf"),
      iat = extractLong(value, "iat"),
      jti = extractString(value, "jti"),
      content = filterClaimFields(value)
    )
    case _ => throw new RuntimeException("Expected a JObject")
  }

  def writeClaim(claim: JwtClaim[JValue]): JValue = {
    val value = {
      ("iss" -> claim.iss) ~
      ("sub" -> claim.sub) ~
      ("aud" -> claim.aud) ~
      ("exp" -> claim.exp) ~
      ("nbf" -> claim.nbf) ~
      ("iat" -> claim.iat) ~
      ("jti" -> claim.jti)
    }.removeField {
      case (_, JNothing) => true
      case (_, _) => false
    }

    value.merge(claim.content)
  }

  def readHeader(json: JValue): JwtHeader = json match {
    case value: JObject => JwtHeader.apply(
      alg = extractString(value, "alg").flatMap(JwtAlgorithm.optionFromString),
      typ = extractString(value, "typ"),
      cty = extractString(value, "cty")
    )
    case _ => throw new RuntimeException("Expected a JObject")
  }

  def writeHeader(header: JwtHeader): JValue = {
    {
      ("typ" -> header.typ) ~
      ("alg" -> header.alg.map(_.name).orElse(Option("none"))) ~
      ("cty" -> header.cty)
    }.removeField {
      case (_, JNothing) => true
      case (_, _) => false
    }
  }

  private def extractString(json: JObject, fieldName: String): Option[String] = json \ fieldName match {
    case JString(value) => Option(value)
    case JNull | JNothing => None
    case _ => throw new JwtNonStringException(fieldName)
  }

  private def extractLong(json: JObject, fieldName: String): Option[Long] = json \ fieldName match {
    case JInt(value) => Option(value.toLong)
    case JNull | JNothing => None
    case _ => throw new JwtNonNumberException(fieldName)
  }

  private def filterClaimFields(json: JObject): JObject = json removeField {
    case JField("iss", _) => true
    case JField("sub", _) => true
    case JField("aud", _) => true
    case JField("exp", _) => true
    case JField("nbf", _) => true
    case JField("iat", _) => true
    case JField("jti", _) => true
    case _ => false
  } match {
    case res: JObject => res
    case _ => throw new RuntimeException("How did we manage to go from JObject to something else by just removing fields?")
  }

  def parseHeader(header: JValue): JwtHeader = readHeader(header)
  def parseClaim(claim: JValue): JwtClaim[JValue] = readClaim(claim)

  def parseHeader(header: String): JwtHeader = readHeader(parse(header))
  def parseClaim(claim: String): JwtClaim[JValue] = readClaim(parse(claim))
}
