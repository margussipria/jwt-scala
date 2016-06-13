package eu.sipria.play.jwt

import java.security.Key

import _root_.play.api.Application
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json._
import eu.sipria.jwt._
import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtHmacAlgorithm, JwtRSAAlgorithm}

import scala.util.Try

/** Similar to the default Play Session but using JsObject instead of Map[String, String]. The data is separated into two attributes:
  * `headerData` and `claimData`. There is also a optional signature. Most of the time, you should only care about the `claimData` which
  * stores the claim of the token containing the custom values you eventually put in it. That's why all methods of `JwtSession` (such as
  * add and removing values) only modify the `claimData`.
  *
  * To see a full list of samples, check the [[http://pauldijou.fr/jwt-scala/samples/jwt-play/ online documentation]].
  *
  * '''Warning''' Be aware that if you override the `claimData` (using `withClaim` for example), you might override some attributes that
  * were automatically put inside the claim such as the expiration of the token.
  */
case class JwtSession(headerData: JsObject, claimData: JsObject) {
  /** Merge the `value` with `claimData` */
  def + (value: JsObject): JwtSession = this.copy(claimData = claimData.deepMerge(value))

  /** Add this (key, value) to `claimData` (existing key will be overridden) */
  def + (key: String, value: JsValueWrapper): JwtSession = this + Json.obj(key -> value)

  /** Convert `value` to its JSON counterpart and add it to `claimData` */
  def + [T](key: String, value: T)(implicit writer: Writes[T]): JwtSession = this + Json.obj(key -> writer.writes(value))

  /** Add a sequence of (key, value) to `claimData` */
  def ++ (fields: (String, JsValueWrapper)*): JwtSession = this + Json.obj(fields: _*)

  /** Remove one key from `claimData` */
  def - (fieldName: String): JwtSession = this.copy(claimData = claimData - fieldName)

  /** Remove a sequence of keys from `claimData` */
  def -- (fieldNames: String*): JwtSession = this.copy(claimData = fieldNames.foldLeft(claimData) {
    (data, fieldName) => data - fieldName
  })

  /** Retrieve the value corresponding to `fieldName` from `claimData` */
  def get(fieldName: String): Option[JsValue] = (claimData \ fieldName).toOption

  /** After retrieving the value, try to read it as T, if no value or fails, returns None. */
  def getAs[T](fieldName: String)(implicit reader: Reads[T]): Option[T] = {
    get(fieldName).flatMap(value => reader.reads(value).asOpt)
  }

  /** Alias of `get` */
  def apply(fieldName: String): Option[JsValue] = get(fieldName)

  def isEmpty: Boolean = claimData.keys.isEmpty

  def claim: JwtClaim[JsObject] = jwtClaimReader.reads(claimData).get
  def header: JwtHeader = jwtHeaderReader.reads(headerData).get

  /** Encode the session as a JSON Web Token */
  def serialize(implicit app: Application): String = JwtSession.getSigningKey match {
    case Some(key) =>
      JwtToken.encode(headerData, claimData, key).token
    case _ =>
      JwtToken.encode(headerData, claimData).token
  }

  /** Override the `claimData` */
  def withClaim(claim: JwtClaim[JsObject]): JwtSession = this.copy(claimData = JwtSession.asJsObject(claim))

  /** Override the `headerData` */
  def withHeader(header: JwtHeader): JwtSession = this.copy(headerData = JwtSession.asJsObject(header))

  /** If your Play app config has a `session.maxAge`, it will extend the expiration by that amount */
  def refresh(implicit jwtTime: JwtTime, app: Application): JwtSession = {
    JwtSession.getMaxAge.map(sec => this + ("exp", jwtTime.now + sec)).getOrElse(this)
  }
}

object JwtSession {
  // This half-hack is to fix a "bug" in Play Framework where Play assign "null"
  // values to missing keys leading to ConfigException.Null in Typesafe Config
  // Especially strange for the maxAge key. Not having it should mean no session timeout,
  // not crash my app.
  def wrap[T](getter: => Option[T]): Option[T] = try {
    getter
  } catch {
    case e: com.typesafe.config.ConfigException.Null => None
    case e: java.lang.RuntimeException =>
      e.getCause match {
        case _: com.typesafe.config.ConfigException.Null => None
        case _ => throw e
      }
  }

  def getConfigBoolean(key: String)(implicit app: Application): Option[Boolean] = wrap[Boolean](app.configuration.getBoolean(key))

  def getConfigString(key: String)(implicit app: Application): Option[String] = wrap[String](app.configuration.getString(key))

  def getConfigMillis(key: String)(implicit app: Application): Option[Long] = wrap[Long](app.configuration.getMilliseconds(key))

  def getHeaderName(implicit app: Application): String = getConfigString("eu.sipria.play.jwt.name").getOrElse("Authorization")

  def getMaxAge(implicit app: Application): Option[Long] = getConfigMillis("play.http.session.maxAge").map(_ / 1000)

  def getAlgorithm(implicit app: Application): JwtAlgorithm = {
    getConfigString("eu.sipria.play.jwt.algorithm")
      .map(JwtAlgorithm.fromString)
      .flatMap {
        case alg: JwtHmacAlgorithm => Option(alg)
        case alg: JwtRSAAlgorithm => Option(alg)
        case _ => throw new RuntimeException("You can only use HMAC algorithms for [eu.sipria.play.jwt.algorithm]")
      }
      .getOrElse(JwtAlgorithm.HmacSHA256)
  }

  def getTokenPrefix(implicit app: Application): String = getConfigString("eu.sipria.play.jwt.token.prefix").map(_.trim).getOrElse("Bearer")

  private def getPublicVerifyKey(key: String, base64: Boolean, `type`: String)(implicit app: Application): Option[Key] = {
    getConfigString(key) map { public =>
      val file = scala.io.Source.fromFile(public, "ISO-8859-1").mkString
      base64 match {
        case true => JwtUtils.getVerifyKeyFromBase64(file, getAlgorithm)
        case false => JwtUtils.parsePublicKey(file.getBytes("UTF-8"), `type`)
      }
    }
  }

  private def getVerifyKey(implicit app: Application): Option[Key] = {
    val base64: Boolean = getConfigBoolean("eu.sipria.play.jwt.key.base64").getOrElse(false)

    getConfigString("eu.sipria.play.jwt.key.type") match {
      case Some(JwtUtils.HMAC) =>
        getConfigString("eu.sipria.play.jwt.key.hmac.secret") map { secret =>
          base64 match {
            case true => JwtUtils.getVerifyKeyFromBase64(secret, getAlgorithm)
            case false => JwtUtils.getVerifyKey(secret.getBytes("UTF-8"), getAlgorithm)
          }
        }

      case Some(JwtUtils.RSA) => getPublicVerifyKey("eu.sipria.play.jwt.key.rsa.public", base64, JwtUtils.RSA)

      case Some(JwtUtils.ECDSA) => getPublicVerifyKey("eu.sipria.play.jwt.key.ecdsa.public", base64, JwtUtils.ECDSA)

      case value => throw new Exception(s"Jwt key type [${value.getOrElse("-")}] is not supported")
    }
  }

  private def getPrivateSigningKey(key: String, base64: Boolean, `type`: String)(implicit app: Application): Option[Key] = {
    getConfigString(key) map { public =>
      val file = scala.io.Source.fromFile(public, "ISO-8859-1").mkString
      base64 match {
        case true => JwtUtils.getSigningKeyFromBase64(file, getAlgorithm)
        case false => JwtUtils.parsePrivateKey(file.getBytes("UTF-8"), `type`)
      }
    }
  }

  private def getSigningKey(implicit app: Application): Option[Key] = {
    val base64: Boolean = getConfigBoolean("eu.sipria.play.jwt.key.base64").getOrElse(false)

    getConfigString("eu.sipria.play.jwt.key.type") match {
      case Some(JwtUtils.HMAC) =>
        getConfigString("eu.sipria.play.jwt.key.hmac.secret") map { secret =>
          base64 match {
            case true => JwtUtils.getVerifyKeyFromBase64(secret, getAlgorithm)
            case false => JwtUtils.getVerifyKey(secret.getBytes("UTF-8"), getAlgorithm)
          }
        }

      case Some(JwtUtils.RSA) => getPrivateSigningKey("eu.sipria.play.jwt.key.rsa.private", base64, JwtUtils.RSA)

      case Some(JwtUtils.ECDSA) => getPrivateSigningKey("eu.sipria.play.jwt.key.ecdsa.private", base64, JwtUtils.RSA)

      case value => throw new Exception(s"Jwt key type [${value.getOrElse("-")}] is not supported")
    }
  }

  def deserialize(token: String, options: JwtOptions)(implicit jwtTime: JwtTime, app: Application): JwtSession = {

    Try(getVerifyKey).flatMap {
      case Some(key) => JwtToken.decodeAndValidate(token, key, Seq(getAlgorithm), options)
      case None => JwtToken.decodeAndValidate(token, options)
    }
      .map(jwtToken => JwtSession(jwtToken.header, jwtToken.claim))
      .getOrElse(JwtSession())
  }

  def deserialize(token: String)(implicit jwtTime: JwtTime, app: Application): JwtSession = deserialize(token, JwtOptions.DEFAULT)

  private def asJsObject[A](value: A)(implicit writer: Writes[A]): JsObject = writer.writes(value) match {
    case value: JsObject => value
    case _ => Json.obj()
  }

  def defaultHeader(implicit app: Application): JwtHeader = JwtHeader(getAlgorithm)

  def defaultClaim(implicit jwtTime: JwtTime, app: Application): JwtClaim[JsObject] = getMaxAge match {
    case Some(seconds) => JwtClaim(content = JsObject.apply(Seq.empty)).expiresIn(seconds)
    case _ => JwtClaim(content = JsObject.apply(Seq.empty))
  }

  def apply(jsClaim: JsObject)(implicit app: Application): JwtSession = {
    JwtSession.apply(asJsObject(defaultHeader), jsClaim)
  }

  def apply(fields: (String, JsValueWrapper)*)(implicit jwtTime: JwtTime, app: Application): JwtSession = {
    if (fields.isEmpty) {
      JwtSession.apply(defaultHeader, defaultClaim)
    } else {
      JwtSession.apply(Json.obj(fields: _*))
    }
  }

  def apply(claim: JwtClaim[JsObject])(implicit app: Application): JwtSession = JwtSession.apply(defaultHeader, claim)

  def apply(header: JwtHeader, claim: JwtClaim[JsObject]): JwtSession = new JwtSession(asJsObject(header), asJsObject(claim))
}
