package eu.sipria.jwt

import org.json4s._
import org.json4s.native.JsonMethods._

trait JwtJson4sNativeFixture extends Json4sCommonFixture {
  def parseString(value: String): JValue = parse(value)
}
