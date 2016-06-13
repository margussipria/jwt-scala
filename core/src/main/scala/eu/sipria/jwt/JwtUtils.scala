package eu.sipria.jwt

import java.security._
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Mac, SecretKey}

import eu.sipria.jwt.algorithms._
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.Arrays

object JwtUtils {
  val PROVIDER = "BC"
  val HMAC = "HMAC"
  val RSA = "RSA"
  val ECDSA = "ECDSA"

  if (Security.getProvider(PROVIDER) == null) {
    Security.addProvider(new BouncyCastleProvider)
  }

  private def parseKey(key: String): Array[Byte] = java.util.Base64.getDecoder.decode(
    key
      .replaceAll("-----BEGIN (.*)-----", "")
      .replaceAll("-----END (.*)-----", "")
      .replaceAll("\r\n", "")
      .replaceAll("\n", "")
      .trim
  )

  def parsePrivateKey(key: Array[Byte], keyAlg: String): PrivateKey = {
    val spec = new PKCS8EncodedKeySpec(key)
    KeyFactory.getInstance(keyAlg, PROVIDER).generatePrivate(spec)
  }

  def getSigningKey(key: Array[Byte], algorithm: JwtAlgorithm): Key = algorithm match {
    case alg: JwtHmacAlgorithm   => new SecretKeySpec(key, alg.fullName)
    case alg: JwtRSAAlgorithm    => parsePrivateKey(key, RSA)
    case alg: JwtECDSAAlgorithm  => parsePrivateKey(key, ECDSA)
  }

  def getSigningKeyFromBase64(key: String, algorithm: JwtAlgorithm): Key = algorithm match {
    case alg: JwtHmacAlgorithm   => getSigningKey(java.util.Base64.getUrlDecoder.decode(key), algorithm)
    case alg: JwtRSAAlgorithm    => getSigningKey(parseKey(key), algorithm)
    case alg: JwtECDSAAlgorithm  => getSigningKey(parseKey(key), algorithm)
  }

  def parsePublicKey(key: Array[Byte], keyAlg: String): PublicKey = {
    val spec = new X509EncodedKeySpec(key)
    KeyFactory.getInstance(keyAlg, PROVIDER).generatePublic(spec)
  }

  def getVerifyKey(key: Array[Byte], algorithm: JwtAlgorithm): Key = algorithm match {
    case alg: JwtHmacAlgorithm   => new SecretKeySpec(key, alg.fullName)
    case alg: JwtRSAAlgorithm    => parsePublicKey(key, RSA)
    case alg: JwtECDSAAlgorithm  => parsePublicKey(key, ECDSA)
  }

  def getVerifyKeyFromBase64(key: String, algorithm: JwtAlgorithm): Key = algorithm match {
    case alg: JwtHmacAlgorithm   => getVerifyKey(java.util.Base64.getUrlDecoder.decode(key), algorithm)
    case alg: JwtRSAAlgorithm    => getVerifyKey(parseKey(key), algorithm)
    case alg: JwtECDSAAlgorithm  => getVerifyKey(parseKey(key), algorithm)
  }

  /**
    * Generate the signature for a given data using the key and HMAC algorithm provided.
    */
  def sign(data: Array[Byte], key: SecretKey, algorithm: JwtHmacAlgorithm): Array[Byte] = {
    val mac = Mac.getInstance(algorithm.fullName, PROVIDER)
    mac.init(key)
    mac.doFinal(data)
  }

  def sign(data: String, key: SecretKey, algorithm: JwtHmacAlgorithm): Array[Byte] = {
    sign(data.getBytes("UTF-8"), key, algorithm)
  }

  /**
    * Generate the signature for a given data using the key and RSA or ECDSA algorithm provided.
    */
  def sign(data: Array[Byte], key: PrivateKey, algorithm: JwtAsymmetricAlgorithm): Array[Byte] = {
    val signer = Signature.getInstance(algorithm.fullName, PROVIDER)
    signer.initSign(key)
    signer.update(data)
    signer.sign
  }

  def sign(data: String, key: PrivateKey, algorithm: JwtAsymmetricAlgorithm): Array[Byte] = {
    sign(data.getBytes("UTF-8"), key, algorithm)
  }

  private val isEqual: (Array[Byte], Array[Byte]) => Boolean = Arrays.constantTimeAreEqual

  /**
    * Check if a signature is valid for a given data using the key and the HMAC algorithm provided.
    */
  def verify(data: Array[Byte], signature: Array[Byte], key: SecretKey, algorithm: JwtHmacAlgorithm): Boolean = {
    isEqual(sign(data, key, algorithm), signature)
  }

  /**
    * Check if a signature is valid for a given data using the key and the RSA or ECDSA algorithm provided.
    */
  def verify(data: Array[Byte], signature: Array[Byte], key: PublicKey, algorithm: JwtAsymmetricAlgorithm): Boolean = {
    val signer = Signature.getInstance(algorithm.fullName, PROVIDER)
    signer.initVerify(key)
    signer.update(data)
    signer.verify(signature)
  }

  /**
    * Will try to check if a signature is valid for a given data by parsing the provided key, if parsing fail, please consider retrieving the SecretKey or the PublicKey on your side and then use another "verify" method.
    */
  def verify(data: Array[Byte], signature: Array[Byte], key: Key, algorithm: JwtAlgorithm): Boolean = {
    (key, algorithm) match {
      case (key: SecretKey, alg: JwtHmacAlgorithm)  => verify(data, signature, key, alg)
      case (key: PublicKey, alg: JwtRSAAlgorithm)   => verify(data, signature, key, alg)
      case (key: PublicKey, alg: JwtECDSAAlgorithm) => verify(data, signature, key, alg)
      case _ => false
    }
  }
}
