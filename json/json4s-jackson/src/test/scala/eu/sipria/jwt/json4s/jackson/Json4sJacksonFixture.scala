package eu.sipria.jwt.json4s.jackson

import eu.sipria.jwt.json4s.Json4sCommonFixture
import org.json4s._
import org.json4s.jackson.JsonMethods._

trait Json4sJacksonFixture extends Json4sCommonFixture {
  def parseString(value: String): JValue = parse(value)
}
