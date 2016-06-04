package eu.sipria.jwt.circe

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.exceptions.JwtNonStringException
import eu.sipria.jwt.{JwtClaim, JwtCore, JwtHeader, JwtJson}
import io.circe.jawn.{parse => jawnParse}
import io.circe.syntax._
import io.circe.{HCursor, Json}

/**
  * Implementation of `JwtCore` using `Json` from Circe.
  */
object JwtCirce extends JwtCore[Json] {
  def parse(value: String): Json = jawnParse(value).toOption.get
  def stringify(value: Json): String = value.asJson.noSpaces
  def getAlgorithm(header: Json): Option[JwtAlgorithm] = getAlg(header.hcursor)

  private def getAlg(cursor: HCursor): Option[JwtAlgorithm] = {
    cursor.get[String]("alg").toOption.flatMap {
      case "none" => None
      case s if s == null => None
      case s: String => Option(JwtAlgorithm.fromString(s))
      case _ => throw new JwtNonStringException("alg")
    }
  }

  def getJson(jwtJson: JwtJson): Json = jwtJson match {
    case header: JwtHeader => Json.fromFields(Seq(
      header.typ
        .map(Json.fromString).map("typ" -> _),
      header.alg.map(_.name).orElse(Option("none"))
        .map(Json.fromString).map("alg" -> _),
      header.cty
        .map(Json.fromString).map("cty" -> _)
    ).flatten)
    case claim: JwtClaim[Json] =>
      val value = Json.fromFields(Seq(
        claim.iss.map(Json.fromString).map("iss" -> _),
        claim.sub.map(Json.fromString).map("sub" -> _),
        claim.aud.map(Json.fromString).map("aud" -> _),
        claim.exp.map(Json.fromLong).map("exp" -> _),
        claim.nbf.map(Json.fromLong).map("nbf" -> _),
        claim.iat.map(Json.fromLong).map("iat" -> _),
        claim.jti.map(Json.fromString).map("jti" -> _)
      ).flatten)

      claim.content.deepMerge(value)
  }

  def parseHeader(header: Json): JwtHeader = {
    val cursor = header.hcursor
    JwtHeader(
      alg = getAlg(cursor),
      typ = cursor.get[String]("typ").toOption,
      cty = cursor.get[String]("cty").toOption
    )
  }

  def parseClaim(claim: Json): JwtClaim[Json] = {
    val cursor = claim.hcursor
    val contentCursor = List("iss", "sub", "aud", "exp", "nbf", "iat", "jti").foldLeft(cursor) { (cursor, field) =>
      val newCursor = cursor.downField(field).delete
      if(newCursor.succeeded) newCursor.any
      else cursor
    }
    JwtClaim(
      content = contentCursor.top.asJson,
      iss = cursor.get[String]("iss").toOption,
      sub = cursor.get[String]("sub").toOption,
      aud = cursor.get[String]("aud").toOption,
      exp = cursor.get[Long]("exp").toOption,
      nbf = cursor.get[Long]("nbf").toOption,
      iat = cursor.get[Long]("iat").toOption,
      jti = cursor.get[String]("jti").toOption
    )
  }

  def parseHeader(header: String): JwtHeader = parseHeader(parse(header))
  def parseClaim(claim: String): JwtClaim[Json] = parseClaim(parse(claim))
}
