package eu.sipria.jwt

import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtHmacAlgorithm}
import play.api.Play
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json._

import scala.util.Try

/** Similar to the default Play Session but using JsObject instead of Map[String, String]. The data is separated into two attributes:
  * `headerData` and `claimData`. There is also a optional signature. Most of the time, you should only care about the `claimData` which
  * stores the claim of the token containing the custom values you eventually put in it. That's why all methods of `JwtSession` (such as
  * add and removing values) only modifiy the `claimData`.
  *
  * To see a full list of samples, check the [[http://pauldijou.fr/jwt-scala/samples/jwt-play/ online documentation]].
  *
  * '''Warning''' Be aware that if you override the `claimData` (using `withClaim` for example), you might override some attributes that
  * were automatically put inside the claim such as the expiration of the token.
  *
  */
case class JwtSession(headerData: JsObject, claimData: JsObject) {
  implicit val jwtJson = JwtPlayJson

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
  def getAs[T](fieldName: String)(implicit reader: Reads[T]): Option[T] =
    get(fieldName).flatMap(value => reader.reads(value).asOpt)

  /** Alias of `get` */
  def apply(fieldName: String): Option[JsValue] = get(fieldName)

  def isEmpty: Boolean = claimData.keys.isEmpty

  def claim: JwtClaim = jwtClaimReader.reads(claimData).get
  def header: JwtHeader = jwtHeaderReader.reads(headerData).get

  /** Encode the session as a JSON Web Token */
  def serialize: String = JwtSession.key match {
    case Some(k) =>
      JwtToken(headerData, claimData, JwtUtils.getSigningKey(k.getBytes("UTF-8"), JwtSession.ALGORITHM)).token
    case _ =>
      JwtToken(headerData, claimData).token
  }

  /** Override the `claimData` */
  def withClaim(claim: JwtClaim): JwtSession = this.copy(claimData = JwtSession.asJsObject(claim))

  /** Override the `headerData` */
  def withHeader(header: JwtHeader): JwtSession = this.copy(headerData = JwtSession.asJsObject(header))

  /** If your Play app config has a `session.maxAge`, it will extend the expiration by that amount */
  def refresh(implicit jwtTime: JwtTime): JwtSession = JwtSession.MAX_AGE.map(sec => this + ("exp", jwtTime.now + sec)).getOrElse(this)
}

object JwtSession {
  implicit val jwtJson = JwtPlayJson

  // This half-hack is to fix a "bug" in Play Framework where Play assign "null"
  // values to missing keys leading to ConfigException.Null in Typesafe Config
  // Especially strange for the maxAge key. Not having it should mean no session timeout,
  // not crash my app.
  def wrap[T](getter: String => Option[T]): String => Option[T] = key => try {
    getter(key)
  } catch {
    case e: com.typesafe.config.ConfigException.Null => None
    case e: java.lang.RuntimeException =>
      e.getCause match {
        case _: com.typesafe.config.ConfigException.Null => None
        case _ => throw e
      }
  }

  val getConfigString = wrap[String](
    key => Play.maybeApplication.flatMap(_.configuration.getString(key))
  )

  val getConfigMillis = wrap[Long](
    key => Play.maybeApplication.flatMap(_.configuration.getMilliseconds(key))
  )

  val HEADER_NAME: String = getConfigString("play.http.session.jwtName").getOrElse("Authorization")

  val MAX_AGE: Option[Long] = getConfigMillis("play.http.session.maxAge").map(_ / 1000)

  val ALGORITHM: JwtHmacAlgorithm = {
    getConfigString("play.http.session.algorithm")
      .map(JwtAlgorithm.fromString)
      .flatMap {
        case algo: JwtHmacAlgorithm => Option(algo)
        case _ => throw new RuntimeException("You can only use HMAC algorithms for [play.http.session.algorithm]")
      }
      .getOrElse(JwtAlgorithm.HmacSHA256)
  }

  val TOKEN_PREFIX: String = getConfigString("play.http.session.tokenPrefix").getOrElse("Bearer ")

  private def key: Option[String] = getConfigString("play.crypto.secret")

  def deserialize(token: String, options: JwtOptions)(implicit jwtTime: JwtTime): JwtSession = {
    val jwtToken = JwtToken(token)

    Try (key match {
      case Some(k) if jwtToken.isValid(JwtUtils.getVerifyKey(k.getBytes("UTF-8"), ALGORITHM), Seq(ALGORITHM), options) => jwtToken
      case None if jwtToken.isValid(options) => jwtToken
    })
      .map(jwtToken => JwtSession(jwtToken.header, jwtToken.claim))
      .getOrElse(JwtSession())
  }

  def deserialize(token: String)(implicit jwtTime: JwtTime): JwtSession = deserialize(token, JwtOptions.DEFAULT)

  private def asJsObject[A](value: A)(implicit writer: Writes[A]): JsObject = writer.writes(value) match {
    case value: JsObject => value
    case _ => Json.obj()
  }

  def defaultHeader: JwtHeader = key.map(_ => JwtHeader(ALGORITHM)).getOrElse(JwtHeader())

  def defaultClaim(implicit jwtTime: JwtTime): JwtClaim = MAX_AGE match {
    case Some(seconds) => JwtClaim().expiresIn(seconds)
    case _ => JwtClaim()
  }

  def apply(jsClaim: JsObject): JwtSession =
    JwtSession.apply(asJsObject(defaultHeader), jsClaim)

  def apply(fields: (String, JsValueWrapper)*)(implicit jwtTime: JwtTime): JwtSession = {
    if (fields.isEmpty) {
      JwtSession.apply(defaultHeader, defaultClaim)
    } else {
      JwtSession.apply(Json.obj(fields: _*))
    }
  }

  def apply(claim: JwtClaim): JwtSession = JwtSession.apply(defaultHeader, claim)

  def apply(header: JwtHeader, claim: JwtClaim): JwtSession = new JwtSession(asJsObject(header), asJsObject(claim))
}
