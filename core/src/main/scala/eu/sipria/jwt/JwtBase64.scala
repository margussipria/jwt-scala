package eu.sipria.jwt

import scala.language.implicitConversions

object JwtBase64 {
  private lazy val encoder = java.util.Base64.getUrlEncoder
  private lazy val decoder = java.util.Base64.getUrlDecoder

  implicit private def getBytes(string: String): Array[Byte] = string.getBytes("UTF-8")
  implicit private def stringify(bytes: Array[Byte]): String = new String(bytes, "UTF-8")

  //def decode(value: Array[Byte]): Array[Byte] = decoder.decode(value)
  def decode(value: String): Array[Byte] = decoder.decode(value)

  //def decodeString(value: Array[Byte]): String = decoder.decode(value)
  def encodeString(value: Array[Byte]): String = encoder.encodeToString(value).replaceAll("=", "")

  def decodeString(value: String): String = decoder.decode(value)
  def encodeString(value: String): String = encoder.encodeToString(value).replaceAll("=", "")
}
