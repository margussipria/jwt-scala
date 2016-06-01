package pdi.jwt

/**
  * Default implementation of [[JwtCore]] using only Strings. Most of the time, you should use a lib
  * implementing JSON and shouldn't be using this object. But just in case you need pure Scala support,
  * here it is.
  *
  * To see a full list of samples, check the [[http://pauldijou.fr/jwt-scala/samples/jwt-core/ online documentation]].
  *
  * '''Warning''': since there is no JSON support in Scala, this object doesn't have any way to parse
  * a JSON string as an AST, so it only uses regex with all the limitations it implies. Try not to use
  * keys like `exp` and `nbf` in sub-objects of the claim. For example, if you try to use the following
  * claim: `{"user":{"exp":1},"exp":1300819380}`, it should be correct but it will fail because the regex
  * extracting the expiration will return `1` instead of `1300819380`. Sorry about that.
  */
object Jwt extends JwtCore[String, String] {
  protected def parseHeader(header: String): String = header
  protected def parseClaim(claim: String): String = claim

  private val extractAlgorithmRegex = "\"alg\":\"([a-zA-Z0-9]+)\"".r
  protected def extractAlgorithm(header: String): Option[JwtAlgorithm] = {
    (extractAlgorithmRegex findFirstMatchIn header).map(_.group(1)).flatMap {
      case "none" => None
      case name: String => Some(JwtAlgorithm.fromString(name))
    }
  }

  private val extractExpirationRegex = "\"exp\":([0-9]+)".r
  protected def extractExpiration(claim: String): Option[Long] = {
    (extractExpirationRegex findFirstMatchIn claim).map(_.group(1)).map(_.toLong)
  }

  private val extractNotBeforeRegex = "\"nbf\":([0-9]+)".r
  protected def extractNotBefore(claim: String): Option[Long] = {
    (extractNotBeforeRegex findFirstMatchIn claim).map(_.group(1)).map(_.toLong)
  }
}
