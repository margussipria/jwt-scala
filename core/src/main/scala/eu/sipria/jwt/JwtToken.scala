package eu.sipria.jwt

import java.security.{Key, PrivateKey}
import javax.crypto.SecretKey

import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtAsymmetricAlgorithm, JwtHmacAlgorithm}
import eu.sipria.jwt.exceptions._

import scala.util.{Failure, Success, Try}

case class JwtToken[JsonType](header: JwtHeader, claim: JwtClaim[JsonType], data: String, signature: String)(implicit jwtJson: JwtCore[JsonType]) {

  lazy val token: String = data + "." + signature

  override def toString: String = token

  protected def validateTiming(options: JwtOptions)(implicit jwtTime: JwtTime): Boolean = {
    val maybeExpiration: Option[Long] = {
      if (options.expiration) claim.exp else None
    }

    val maybeNotBefore: Option[Long] = {
      if (options.notBefore) claim.nbf else None
    }

    jwtTime.validateNowIsBetween(
      maybeNotBefore.map(_ - options.leeway),
      maybeExpiration.map(_ + options.leeway)
    )
  }

  // Validation when both key and algorithm
  protected def validate(options: JwtOptions, verify: (Array[Byte], Array[Byte], JwtAlgorithm) => Boolean)(implicit jwtTime: JwtTime): Boolean = {
    if (options.signature) {
      val maybeAlg = header.alg

      if (options.signature && signature.isEmpty) {
        throw new JwtEmptySignatureException()
      } else if (maybeAlg.isEmpty) {
        throw new JwtEmptyAlgorithmException()
      } else if (!verify(data.getBytes("UTF-8"), JwtBase64.decode(signature), maybeAlg.get)) {
        throw new JwtValidationException("Invalid signature for this token or wrong algorithm.")
      }
    }

    validateTiming(options)
  }

  def validate(options: JwtOptions)(implicit jwtTime: JwtTime): Try[Boolean] = Try {
    if (options.signature && !signature.isEmpty) {
      throw new JwtNonEmptySignatureException()
    } else if (options.signature && header.alg.isDefined) {
      throw new JwtNonEmptyAlgorithmException()
    }

    validateTiming(options)
  }

  def validate(implicit jwtTime: JwtTime): Try[Boolean] = validate(JwtOptions.DEFAULT)

  def validate(key: Key, algorithms: Seq[JwtAlgorithm], options: JwtOptions = JwtOptions.DEFAULT)(implicit jwtTime: JwtTime): Try[Boolean] = Try {
    validate(options, (data: Array[Byte], signature: Array[Byte], algorithm: JwtAlgorithm) => algorithm match {
      case alg: JwtAsymmetricAlgorithm  => validateAlgorithm(alg, algorithms) && JwtUtils.verify(data, signature, key, alg)
      case alg: JwtHmacAlgorithm        => validateAlgorithm(alg, algorithms) && JwtUtils.verify(data, signature, key, alg)
      case _ => false
    })
  }

  // Validate if an algorithm is inside the authorized range
  protected def validateAlgorithm(algorithm: JwtAlgorithm, algorithms: Seq[JwtAlgorithm]): Boolean = {
    algorithms.map(_.fullName).contains(algorithm.fullName)
  }

  def isValid(options: JwtOptions)(implicit jwtTime: JwtTime): Boolean = validate(options).getOrElse(default = false)

  def isValid()(implicit jwtTime: JwtTime): Boolean = isValid(JwtOptions.DEFAULT)

  def isValid(key: Key, algorithms: Seq[JwtAlgorithm], options: JwtOptions = JwtOptions.DEFAULT)(implicit jwtTime: JwtTime) = {
    validate(key, algorithms, options).getOrElse(default = false)
  }
}

object JwtToken {

  /**
    * @return a tuple of (header64, header, claim64, claim, Option(signature as bytes))
    * @throws JwtLengthException if there is not 2 or 3 parts in the token
    */
  private def splitToken(token: String): (String, String, String, String, String) = {
    val parts = token.split("\\.")

    val signature = parts.length match {
      case 2 => ""
      case 3 => parts(2)
      case _ => throw new JwtLengthException(s"Expected token [$token] to be composed of 2 or 3 parts separated by dots.")
    }

    (parts(0), JwtBase64.decodeString(parts(0)), parts(1), JwtBase64.decodeString(parts(1)), signature)
  }

  /** Will decode a JSON Web Token to JwtToken
    *
    * @param token token
    * @return JwtToken that can be validated
    */
  def decode[JsonType](token: String)(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = {
    val (header64, header, claim64, claim, signature) = splitToken(token)
    val data = header64 + "." + claim64
    JwtToken(jwtJson.parseHeader(header), jwtJson.parseClaim(claim), data, signature)
  }

  def decodeAndValidate[JsonType](token: String, options: JwtOptions)(implicit jwtJson: JwtCore[JsonType], jwtTime: JwtTime): Try[JwtToken[JsonType]] = {
    val jwtToken = decode(token)
    jwtToken.validate(options) flatMap {
      case true => Success(jwtToken)
      case false => Failure(new JwtValidationException("Could validate jwt token"))
    }
  }

  def decodeAndValidate[JsonType](token: String)(implicit jwtJson: JwtCore[JsonType], jwtTime: JwtTime): Try[JwtToken[JsonType]] = {
    decodeAndValidate(token, JwtOptions.DEFAULT)
  }

  def decodeAndValidate[JsonType](token: String, key: Key, algorithms: Seq[JwtAlgorithm], options: JwtOptions = JwtOptions.DEFAULT)(
    implicit jwtJson: JwtCore[JsonType],
    jwtTime: JwtTime
  ): Try[JwtToken[JsonType]] = {

    val jwtToken = decode(token)
    jwtToken.validate(key, algorithms, options) flatMap {
      case true => Success(jwtToken)
      case false => Failure(new JwtValidationException("Could validate jwt token"))
    }
  }

  private def validationException: JwtValidationException = new JwtValidationException(
    "The key type doesn't match the algorithm type. It's either a SecretKey and a HMAC algorithm or a PrivateKey and a RSA or ECDSA algorithm. And an algorithm is required of course."
  )

  def encode[JsonType](header: JsonType, claim: JsonType)(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = {

    val data = JwtBase64.encodeString(jwtJson.stringify(header)) + "." + JwtBase64.encodeString(jwtJson.stringify(claim))

    def headerJson = jwtJson.parseHeader(header)
    def claimJson = jwtJson.parseClaim(claim)

    jwtJson.getAlgorithm(header) match {
      case None =>
        new JwtToken(headerJson, claimJson, data, "")
      case _ => throw new JwtNonEmptyAlgorithmException()
    }
  }

  /** An alias to `encode` if you want to use case classes for the header and the claim rather than strings, they will just be stringified to JSON format.
    *
    * @return token
    * @param header the header to stringify as a JSON before encoding the token
    * @param claim the claim to stringify as a JSON before encoding the token
    */
  def encode[JsonType](header: JwtHeader, claim: JwtClaim[JsonType])(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = header.alg match {
    case None => encode(jwtJson.writeHeader(header), jwtJson.writeClaim(claim))
    case _ => throw new JwtNonEmptyAlgorithmException()
  }

  def encode[JsonType](header: JsonType, claim: JsonType, key: Key)(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = {

    val data = JwtBase64.encodeString(jwtJson.stringify(header)) + "." + JwtBase64.encodeString(jwtJson.stringify(claim))

    def headerJson = jwtJson.parseHeader(header)
    def claimJson = jwtJson.parseClaim(claim)

    (headerJson.alg, key) match {
      case (Some(alg: JwtHmacAlgorithm), key: SecretKey)        =>
        new JwtToken(headerJson, claimJson, data, JwtBase64.encodeString(JwtUtils.sign(data, key, alg)))
      case (Some(alg: JwtAsymmetricAlgorithm), key: PrivateKey) =>
        new JwtToken(headerJson, claimJson, data, JwtBase64.encodeString(JwtUtils.sign(data, key, alg)))
      case _ => throw validationException
    }
  }


  /** An alias to `encode` which will provide an automatically generated header and allowing you to get rid of Option
    * for the key and the algorithm.
    *
    * @return token
    * @param claim claimString
    * @param key key
    * @param algorithm algorithm
    */
  def encode[JsonType](claim: JwtClaim[JsonType], key: Key, algorithm: JwtAlgorithm)(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = {
    encode(jwtJson.writeHeader(JwtHeader(algorithm)), jwtJson.writeClaim(claim), key)
  }

  /** An alias of `encode` if you only want to pass a string as the key, the algorithm will be deduced from the header.
    *
    * @return token
    * @param header the header to stringify as a JSON before encoding the token
    * @param claim the claim to stringify as a JSON before encoding the token
    * @param key the secret key to use to sign the token (note that the algorithm will be deduced from the header)
    */
  def encode[JsonType](header: JwtHeader, claim: JwtClaim[JsonType], key: Key)(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = {
    encode(jwtJson.writeHeader(header), jwtJson.writeClaim(claim), key)
  }
}
