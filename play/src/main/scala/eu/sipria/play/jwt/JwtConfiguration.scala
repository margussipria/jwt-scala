package eu.sipria.play.jwt

import java.security.Key

import com.google.inject.Inject
import eu.sipria.jwt.algorithms.{JwtAlgorithm, JwtECDSAAlgorithm, JwtHmacAlgorithm, JwtRSAAlgorithm}
import eu.sipria.jwt.exceptions.JwtException
import eu.sipria.jwt.{JwtOptions, JwtUtils}
import play.api.{Application, Configuration}

class JwtConfiguration @Inject()(app: Application) {

  // This half-hack is to fix a "bug" in Play Framework where Play assign "null"
  // values to missing keys leading to ConfigException.Null in Typesafe Config
  // Especially strange for the maxAge key. Not having it should mean no session timeout,
  // not crash my app.
  private def wrap[T](getter: => Option[T]): Option[T] = try {
    getter
  } catch {
    case e: com.typesafe.config.ConfigException.Null => None
    case e: java.lang.RuntimeException =>
      e.getCause match {
        case _: com.typesafe.config.ConfigException.Null => None
        case _ => throw e
      }
  }

  private def getConfigBoolean(key: String): Option[Boolean] = wrap[Boolean](app.configuration.getBoolean(key))

  private def getConfigString(key: String): Option[String] = wrap[String](app.configuration.getString(key))

  private def getConfigMillis(key: String): Option[Long] = wrap[Long](app.configuration.getMilliseconds(key))

  val headerName: String = getConfigString("eu.sipria.play.jwt.name").getOrElse("Authorization")

  val maxAge: Option[Long] = getConfigMillis("play.http.session.maxAge").map(_ / 1000)

  val options: JwtOptions = {
    wrap[Configuration](app.configuration.getConfig("eu.sipria.play.jwt.options")).map { options =>
      JwtOptions(
        signature = wrap[Boolean](options.getBoolean("signature")).getOrElse(default = true),
        issuer = wrap[String](options.getString("issuer")),
        subject = wrap[String](options.getString("subject")),
        audience = wrap[String](options.getString("audience")),
        issuedAt = wrap[Long](options.getLong("issuedAt")),
        jwtId = wrap[String](options.getString("jwtId")),
        expiration = wrap[Boolean](options.getBoolean("expiration")).getOrElse(default = true),
        notBefore = wrap[Boolean](options.getBoolean("notBefore")).getOrElse(default = true),
        leeway = wrap[Long](options.getLong("leeway")).getOrElse(default = 0)
      )
    }.getOrElse(JwtOptions())
  }

  val algorithm: Option[JwtAlgorithm] = getConfigString("eu.sipria.play.jwt.algorithm").flatMap(JwtAlgorithm.optionFromString)

  val tokenPrefix: String = getConfigString("eu.sipria.play.jwt.token.prefix").map(_.trim).getOrElse("Bearer")

  private def getPublicVerifyKey(key: String, base64: Boolean, `type`: String, algorithm: JwtAlgorithm): Option[Key] = {
    getConfigString(key) map { public =>
      val file = scala.io.Source.fromFile(public, "ISO-8859-1").mkString
      base64 match {
        case true => JwtUtils.getVerifyKeyFromBase64(file, algorithm)
        case false => JwtUtils.parsePublicKey(file.getBytes("UTF-8"), `type`)
      }
    }
  }

  val verifyKey: Option[Key] = {
    val base64: Boolean = getConfigBoolean("eu.sipria.play.jwt.key.base64").getOrElse(false)

    algorithm flatMap {
      case algorithm: JwtHmacAlgorithm =>
        getConfigString("eu.sipria.play.jwt.key.hmac.secret") map { secret =>
          base64 match {
            case true => JwtUtils.getVerifyKeyFromBase64(secret, algorithm)
            case false => JwtUtils.getVerifyKey(secret.getBytes("UTF-8"), algorithm)
          }
        }

      case algorithm: JwtRSAAlgorithm => getPublicVerifyKey("eu.sipria.play.jwt.key.rsa.public", base64, JwtUtils.RSA, algorithm)

      //case algorithm: JwtECDSAAlgorithm => getPublicVerifyKey("eu.sipria.play.jwt.key.ecdsa.public", base64, JwtUtils.ECDSA, algorithm)
      case algorithm: JwtECDSAAlgorithm => throw new JwtException("ECDSA algorithm is not supported")
    }
  }

  private def getPrivateSigningKey(key: String, base64: Boolean, `type`: String, algorithm: JwtAlgorithm): Option[Key] = {
    getConfigString(key) map { public =>
      val file = scala.io.Source.fromFile(public, "ISO-8859-1").mkString
      base64 match {
        case true => JwtUtils.getSigningKeyFromBase64(file, algorithm)
        case false => JwtUtils.parsePrivateKey(file.getBytes("UTF-8"), `type`)
      }
    }
  }

  val signingKey: Option[Key] = {
    val base64: Boolean = getConfigBoolean("eu.sipria.play.jwt.key.base64").getOrElse(false)

    algorithm flatMap {
      case algorithm: JwtHmacAlgorithm =>
        getConfigString("eu.sipria.play.jwt.key.hmac.secret") map { secret =>
          base64 match {
            case true => JwtUtils.getVerifyKeyFromBase64(secret, algorithm)
            case false => JwtUtils.getVerifyKey(secret.getBytes("UTF-8"), algorithm)
          }
        }

      case algorithm: JwtRSAAlgorithm => getPrivateSigningKey("eu.sipria.play.jwt.key.rsa.private", base64, JwtUtils.RSA, algorithm)

      //case algorithm: JwtECDSAAlgorithm => getPrivateSigningKey("eu.sipria.play.jwt.key.ecdsa.private", base64, JwtUtils.ECDSA, algorithm)
      case algorithm: JwtECDSAAlgorithm => throw new JwtException("ECDSA algorithm is not supported")
    }
  }
}
