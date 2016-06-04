package eu.sipria.jwt.json4s.native

import eu.sipria.jwt.json4s.Json4sCommonFixture
import org.json4s._
import org.json4s.native.JsonMethods._

trait JwtJson4sNativeFixture extends Json4sCommonFixture {
  def parseString(value: String): JValue = parse(value)
}
