package eu.sipria.jwt

import java.security.{Key, PrivateKey}
import javax.crypto.SecretKey

import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtAsymmetricAlgorithm, JwtHmacAlgorithm}
import eu.sipria.jwt.exceptions._

import scala.util.{Failure, Success, Try}

case class JwtToken[JsonType](header: JwtHeader, claim: JwtClaim[JsonType], data: String, signature: String)(implicit jwtJson: JwtCore[JsonType]) {

  lazy val token: String = data + "." + signature

  override def toString: String = token

  override def equals(that: Any): Boolean = {
    that match {
      case that: JwtToken[_] => token.equals(that.token)
      case that: String => token.equals(that)
      case _ => false
    }
  }

  override def hashCode: Int = token.hashCode

  protected def validateOptions(options: JwtOptions): Boolean = {
    if (options.issuer.isDefined && options.issuer != this.claim.iss) {
      throw new JwtValidationException("Issuer didn't match required iss")
    }

    if (options.subject.isDefined && options.subject != this.claim.sub) {
      throw new JwtValidationException("sub didn't match required sub")
    }

    if (options.audience.isDefined && options.audience != this.claim.aud) {
      throw new JwtValidationException("Audience didn't match required aud")
    }

    if (options.issuedAt.isDefined && options.issuedAt != this.claim.iat) {
      throw new JwtValidationException("Issued at didn't match required iat")
    }

    if (options.jwtId.isDefined && options.jwtId != this.claim.jti) {
      throw new JwtValidationException("Jwt ID at didn't match required jwt")
    }

    validateTiming(options)
  }

  protected def validateTiming(options: JwtOptions): Boolean = {
    val maybeExpiration: Option[Long] = {
      if (options.expiration) claim.exp else None
    }

    val maybeNotBefore: Option[Long] = {
      if (options.notBefore) claim.nbf else None
    }

    JwtTime.validateNowIsBetween(
      maybeNotBefore.map(_ - options.leeway),
      maybeExpiration.map(_ + options.leeway)
    )
  }

  // Validation when both key and algorithm
  protected def validate(options: JwtOptions, verify: (Array[Byte], Array[Byte], JwtAlgorithm) => Boolean): Boolean = {
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

    validateOptions(options)
  }

  def validate(options: JwtOptions): Try[Boolean] = Try {
    if (options.signature && !signature.isEmpty) {
      throw new JwtNonEmptySignatureException()
    } else if (options.signature && header.alg.isDefined) {
      throw new JwtNonEmptyAlgorithmException()
    }

    validateOptions(options)
  }

  def validate: Try[Boolean] = validate(JwtOptions.DEFAULT)

  def validate(key: Key, algorithms: Seq[JwtAlgorithm], options: JwtOptions = JwtOptions.DEFAULT): Try[Boolean] = Try {
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

  def isValid(options: JwtOptions): Boolean = validate(options).getOrElse(default = false)

  def isValid: Boolean = isValid(JwtOptions.DEFAULT)

  def isValid(key: Key, algorithms: Seq[JwtAlgorithm], options: JwtOptions = JwtOptions.DEFAULT) = {
    validate(key, algorithms, options).getOrElse(default = false)
  }
}

object JwtToken {

  /**
    * @return a tuple of (header64, header, claim64, claim, Option(signature as bytes))
    * @throws JwtLengthException if there is not 2 or 3 parts in the token
    */
  private def splitToken(token: String): (String, String, String, String, String) = {
    val Array(header, payload, signature) = token.split("\\.") match {
      case parts if parts.length == 3 => parts
      case parts if parts.length == 2 => parts :+ ""
      case _ => throw new JwtLengthException(s"Expected token [$token] to be composed of 2 or 3 parts separated by dots.")
    }

    (header, JwtBase64.decodeString(header), payload, JwtBase64.decodeString(payload), signature)
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

  def decodeAndValidate[JsonType](token: String, options: JwtOptions)(implicit jwtJson: JwtCore[JsonType]): Try[JwtToken[JsonType]] = {

    Try(decode(token)) flatMap { jwtToken =>
      jwtToken.validate(options) flatMap {
        case true => Success(jwtToken)
        case false => Failure(new JwtValidationException("Could validate jwt token"))
      }
    }
  }

  def decodeAndValidate[JsonType](token: String)(implicit jwtJson: JwtCore[JsonType]): Try[JwtToken[JsonType]] = {
    decodeAndValidate(token, JwtOptions.DEFAULT)
  }

  def decodeAndValidate[JsonType](token: String, key: Key, algorithms: Seq[JwtAlgorithm], options: JwtOptions = JwtOptions.DEFAULT)(
    implicit jwtJson: JwtCore[JsonType]
  ): Try[JwtToken[JsonType]] = {

    Try(decode(token)) flatMap { jwtToken =>
      jwtToken.validate(key, algorithms, options) flatMap {
        case true => Success(jwtToken)
        case false => Failure(new JwtValidationException("Could validate jwt token"))
      }
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
        JwtToken(headerJson, claimJson, data, JwtBase64.encodeString(JwtUtils.sign(data, key, alg)))
      case (Some(alg: JwtAsymmetricAlgorithm), key: PrivateKey) =>
        JwtToken(headerJson, claimJson, data, JwtBase64.encodeString(JwtUtils.sign(data, key, alg)))
      case _ => throw validationException
    }
  }


  /** An alias to `encode` which will provide an automatically generated header and allowing you to get rid of Option for the key and the algorithm.
    *
    * @return token
    * @param claim claimString
    * @param key key
    * @param algorithm algorithm
    */
  def encode[JsonType](claim: JwtClaim[JsonType], key: Key, algorithm: JwtAlgorithm)(implicit jwtJson: JwtCore[JsonType]): JwtToken[JsonType] = {
    encode(jwtJson.writeHeader(JwtHeader(algorithm)), jwtJson.writeClaim(claim), key)
  }

  /** An alias of `encode` if you only want to pass a string as the key
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
