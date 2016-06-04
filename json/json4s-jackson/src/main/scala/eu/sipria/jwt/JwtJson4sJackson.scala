package eu.sipria.jwt

import org.json4s._
import org.json4s.jackson.JsonMethods.{parse => jparse, _}
import org.json4s.jackson.Serialization

/**
  * Implementation of `JwtCore` using `JObject` from Json4s Jackson.
  *
  * To see a full list of samples, check the [[http://pauldijou.fr/jwt-scala/samples/jwt-json4s/ online documentation]].
  */
object JwtJson4sJackson extends JwtJson4sCommon {
  def parse(value: String): JObject = jparse(value) match {
    case res: JObject => res
    case _ => throw new RuntimeException(s"Couldn't parse [$value] to a JObject")
  }

  def stringify(value: JValue): String = compact(render(value))

  protected implicit val formats = Serialization.formats(NoTypeHints)
}
