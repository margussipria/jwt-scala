package eu.sipria.jwt
package json4s
package native

import org.json4s._
import org.json4s.native.JsonMethods.{parse => jparse, _}
import org.json4s.native.Serialization

/**
  * Implementation of `JwtCore` using `JObject` from Json4s Native.
  *
  * To see a full list of samples, check the [[http://pauldijou.fr/jwt-scala/samples/jwt-json4s/ online documentation]].
  */
object JwtJson4sNative extends JwtJson4sCommon {
  def parse(value: String): JValue = jparse(value) match {
    case res: JObject => res
    case _ => throw new RuntimeException(s"Couldn't parse [$value] to a JObject")
  }

  def stringify(value: JValue): String = compact(render(value))

  protected implicit val formats = Serialization.formats(NoTypeHints)
}
