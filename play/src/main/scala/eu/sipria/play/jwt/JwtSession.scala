package eu.sipria.play.jwt

import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json._
import eu.sipria.jwt._

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

  /** After retrieving the value, try to read it as T, if no value or fails, returns None. */
  def getAs[T](implicit reader: Reads[T]): Option[T] = reader.reads(claimData).asOpt

  /** Alias of `get` */
  def apply(fieldName: String): Option[JsValue] = get(fieldName)

  def isEmpty: Boolean = claimData.keys.isEmpty

  def claim: JwtClaim[JsObject] = jwtClaimReader.reads(claimData).get
  def header: JwtHeader = jwtHeaderReader.reads(headerData).get

  /** Encode the session as a JSON Web Token */
  def serialize(implicit configuration: JwtConfiguration): String = configuration.signingKey match {
    case Some(key) =>
      JwtToken.encode(headerData, claimData, key).token
    case None =>
      JwtToken.encode(headerData, claimData).token
  }

  /** Override the `claimData` */
  def withClaim(claim: JwtClaim[JsObject]): JwtSession = this.copy(claimData = JwtSession.asJsObject(claim))

  /** Override the `headerData` */
  def withHeader(header: JwtHeader): JwtSession = this.copy(headerData = JwtSession.asJsObject(header))

  /** If your Play app config has a `session.maxAge`, it will extend the expiration by that amount */
  def refresh(implicit configuration: JwtConfiguration): JwtSession = {
    configuration.maxAge.map(sec => this + ("exp", JwtTime.now + sec)).getOrElse(this)
  }
}

object JwtSession {

  def deserialize(token: String, options: JwtOptions)(implicit configuration: JwtConfiguration): JwtSession = {

    Try(configuration.verifyKey).flatMap {
      case Some(key) => JwtToken.decodeAndValidate(token, key, configuration.algorithm.toSeq, options)
      case None => JwtToken.decodeAndValidate(token, options)
    }
      .map(jwtToken => JwtSession(jwtToken.header, jwtToken.claim))
      .getOrElse(JwtSession())
  }

  def deserialize(token: String)(implicit configuration: JwtConfiguration): JwtSession = deserialize(token, configuration.options)

  private def asJsObject[A](value: A)(implicit writer: Writes[A]): JsObject = writer.writes(value) match {
    case value: JsObject => value
    case _ => Json.obj()
  }

  def defaultHeader(implicit configuration: JwtConfiguration): JwtHeader = {
    configuration.algorithm map JwtHeader.apply getOrElse JwtHeader()
  }

  def defaultClaim(implicit configuration: JwtConfiguration): JwtClaim[JsObject] = configuration.maxAge match {
    case Some(seconds) => JwtClaim(content = JsObject.apply(Seq.empty)).expiresIn(seconds)
    case _ => JwtClaim(content = JsObject.apply(Seq.empty))
  }

  def apply(jsClaim: JsObject)(implicit configuration: JwtConfiguration): JwtSession = {
    JwtSession.apply(asJsObject(defaultHeader), jsClaim)
  }

  def apply(fields: (String, JsValueWrapper)*)(implicit configuration: JwtConfiguration): JwtSession = {
    if (fields.isEmpty) {
      JwtSession.apply(defaultHeader, defaultClaim)
    } else {
      JwtSession.apply(Json.obj(fields: _*))
    }
  }

  def apply(claim: JwtClaim[JsObject])(implicit configuration: JwtConfiguration): JwtSession = JwtSession.apply(defaultHeader, claim)

  def apply(header: JwtHeader, claim: JwtClaim[JsObject]): JwtSession = new JwtSession(asJsObject(header), asJsObject(claim))
}
