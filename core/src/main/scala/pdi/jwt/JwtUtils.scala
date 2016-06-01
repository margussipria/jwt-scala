package pdi.jwt

import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security._
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Mac, SecretKey}

import org.bouncycastle.jce.provider.BouncyCastleProvider
import pdi.jwt.algorithms._

object JwtUtils {
  val ENCODING = "UTF-8"
  val PROVIDER = "BC"
  val RSA = "RSA"
  val ECDSA = "ECDSA"

  if (Security.getProvider(PROVIDER) == null) {
    Security.addProvider(new BouncyCastleProvider())
  }

  /** Convert an array of bytes to its corresponding string using the default encoding.
    *
    * @return the final string
    * @param arr the array of bytes to transform
    */
  def stringify(arr: Array[Byte]): String = new String(arr, ENCODING)

  /** Convert a string to its corresponding array of bytes using the default encoding.
    *
    * @return the final array of bytes
    * @param str the string to convert
    */
  def bytify(str: String): Array[Byte] = str.getBytes(ENCODING)

  private def escape(value: String): String = value.replaceAll("\"", "\\\\\"")

  /** Convert a sequence to a JSON array
    */
  def seqToJson(seq: Seq[Any]): String = if (seq.isEmpty) {
    "[]"
  } else {
    seq.map {
      case value: String => "\"" + escape(value) + "\""
      case value: Boolean => if (value) "true" else "false"
      case value: Double => value.toString
      case value: Short => value.toString
      case value: Float => value.toString
      case value: Long => value.toString
      case value: Int => value.toString
      case value: BigDecimal => value.toString
      case value: BigInt => value.toString
      case (key: String, value: Any) => hashToJson(Seq((key, value)))
      case value: Any => "\"" + escape(value.toString) + "\""
    }.mkString("[", ",", "]")
  }

  /**
    * Convert a sequence of tuples to a JSON object
    */
  def hashToJson(hash: Seq[(String, Any)]): String = if (hash.isEmpty) {
    "{}"
  } else {
    hash.map {
      case (key, value: String) => "\"" + escape(key) + "\":\"" + escape(value) + "\""
      case (key, value: Boolean) => "\"" + escape(key) + "\":" + (if (value) "true" else "false")
      case (key, value: Double) => "\"" + escape(key) + "\":" + value.toString
      case (key, value: Short) => "\"" + escape(key) + "\":" + value.toString
      case (key, value: Float) => "\"" + escape(key) + "\":" + value.toString
      case (key, value: Long) => "\"" + escape(key) + "\":" + value.toString
      case (key, value: Int) => "\"" + escape(key) + "\":" + value.toString
      case (key, value: BigDecimal) => "\"" + escape(key) + "\":" + value.toString
      case (key, value: BigInt) => "\"" + escape(key) + "\":" + value.toString
      case (key, (subKey: String, subValue: Any)) => "\"" + escape(key) + "\":" + hashToJson(Seq((subKey, subValue)))
      case (key, value: Seq[Any]) => "\"" + escape(key) + "\":" + seqToJson(value)
      case (key, value: Any) => "\"" + escape(key) + "\":\"" + escape(value.toString) + "\""
    }.mkString("{", ",", "}")
  }

  /**
    * Merge multiple JSON strings to a unique one
    */
  def mergeJson(json: String, jsonSeq: String*): String = {
    val initJson = json.trim match {
      case "" => ""
      case value => value.drop(1).dropRight(1)
    }

    "{" + jsonSeq.map(_.trim).fold(initJson) {
      case (j1, result) if j1.length < 5 => result.drop(1).dropRight(1)
      case (result, j2) if j2.length < 7 => result
      case (j1, j2) => j1 + "," + j2.drop(1).dropRight(1)
    } + "}"
  }

  private def parseKey(key: String): Array[Byte] = JwtBase64.decodeNonSafe(
    key.replaceAll("-----BEGIN (.*)-----", "")
     .replaceAll("-----END (.*)-----", "")
     .replaceAll("\r\n", "")
     .replaceAll("\n", "")
     .trim
  )

  private def parsePrivateKey(key: String, keyAlgo: String): PrivateKey = {
    val spec = new PKCS8EncodedKeySpec(parseKey(key))
    KeyFactory.getInstance(keyAlgo, PROVIDER).generatePrivate(spec)
  }

  private def parsePublicKey(key: String, keyAlgo: String): PublicKey = {
    val spec = new X509EncodedKeySpec(parseKey(key))
    KeyFactory.getInstance(keyAlgo, PROVIDER).generatePublic(spec)
  }

  /**
    * Generate the signature for a given data using the key and HMAC algorithm provided.
    */
  def sign(data: Array[Byte], key: SecretKey, algorithm: JwtHmacAlgorithm): Array[Byte] = {
    val mac = Mac.getInstance(algorithm.fullName, PROVIDER)
    mac.init(key)
    mac.doFinal(data)
  }

  def sign(data: String, key: SecretKey, algorithm: JwtHmacAlgorithm): Array[Byte] =
    sign(bytify(data), key, algorithm)

  /**
    * Generate the signature for a given data using the key and RSA or ECDSA algorithm provided.
    */
  def sign(data: Array[Byte], key: PrivateKey, algorithm: JwtAsymmetricAlgorithm): Array[Byte] = {
    val signer = Signature.getInstance(algorithm.fullName, PROVIDER)
    signer.initSign(key)
    signer.update(data)
    signer.sign
  }

  def sign(data: String, key: PrivateKey, algorithm: JwtAsymmetricAlgorithm): Array[Byte] =
    sign(bytify(data), key, algorithm)

  /**
    * Will try to sign some given data by parsing the provided key, if parsing fail, please consider retrieving the SecretKey or the PrivateKey on your side and then use another "sign" method.
    */
  def sign(data: Array[Byte], key: String, algorithm: JwtAlgorithm): Array[Byte] =
    algorithm match {
      case algo: JwtHmacAlgorithm => sign(data, new SecretKeySpec(bytify(key), algo.fullName), algo)
      case algo: JwtRSAAlgorithm => sign(data, parsePrivateKey(key, RSA), algo)
      case algo: JwtECDSAAlgorithm => sign(data, parsePrivateKey(key, ECDSA), algo)
    }

  /**
    * Alias to `sign` using a String data which will be converted to an array of bytes.
    */
  def sign(data: String, key: String, algorithm: JwtAlgorithm): Array[Byte] =
    sign(bytify(data), key, algorithm)

  // Fix security vulnerability around timing attacks
  // See http://codahale.com/a-lesson-in-timing-attacks/
  // Thanks to @drbild for report
  private def isEqual(arr1: Array[Byte], arr2: Array[Byte]): Boolean = {
    if (arr1.length != arr2.length) {
      false
    } else {
      var result = 0
      for (i <- arr1.indices) {
        result |= arr1(i) ^ arr2(i)
      }
      result == 0
    }
  }

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
  def verify(data: Array[Byte], signature: Array[Byte], key: String, algorithm: JwtAlgorithm): Boolean =
    algorithm match {
      case algo: JwtHmacAlgorithm =>  verify(data, signature, new SecretKeySpec(bytify(key), algo.fullName), algo)
      case algo: JwtRSAAlgorithm => verify(data, signature, parsePublicKey(key, RSA), algo)
      case algo: JwtECDSAAlgorithm => verify(data, signature, parsePublicKey(key, ECDSA), algo)
    }

  /**
    * Alias for `verify`
    */
  def verify(data: String, signature: String, key: String, algorithm: JwtAlgorithm): Boolean =
    verify(bytify(data), bytify(signature), key, algorithm)
}
