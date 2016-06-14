package eu.sipria.play.jwt

import akka.stream.Materializer
import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt._
import org.scalatest._
import org.scalatestplus.play._
import _root_.play.api.Application
import _root_.play.api.libs.json._
import _root_.play.api.test.Helpers._
import _root_.play.api.test._

class JwtSessionCustomSpec extends PlaySpec with OneAppPerSuite with BeforeAndAfter with PlayFixture {
  val materializer: Materializer = app.materializer

  // Just for test, users shouldn't change the header name normally
  def HEADER_NAME = "Auth"
  def sessionTimeout = 10

  implicit override lazy val app: Application = FakeApplication(
    additionalConfiguration = Map(
      "eu.sipria.play.jwt.key.hmac.secret" -> secretKey,
      "eu.sipria.play.jwt.name" -> HEADER_NAME,
      "play.http.session.maxAge" -> sessionTimeout * 1000, // 10sec... that's really short :)
      "eu.sipria.play.jwt.algorithm" -> "HS512",
      "eu.sipria.play.jwt.token.prefix" -> ""
    )
  )

  def session = JwtSession()
  def sessionCustom = JwtSession(JwtHeader(JwtAlgorithm.HS512), claimClass)
  def tokenCustom = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9." + claim64 + ".ngZsdQj8p2wvUAo8xCbJPwganGPnG5UnLkg7VrE6NgmQdV16UITjlBajZxcai_U5PjQdeN-yJtyA5kxf8O5BOQ"

  "Init FakeApplication" must {
    "have the correct config" in {
      app.configuration.getString("eu.sipria.play.jwt.key.hmac.secret") mustEqual Option(secretKey)
      app.configuration.getString("eu.sipria.play.jwt.name") mustEqual Option(HEADER_NAME)
      app.configuration.getString("eu.sipria.play.jwt.algorithm") mustEqual Option("HS512")
      app.configuration.getString("eu.sipria.play.jwt.token.prefix") mustEqual Option("")
      app.configuration.getMilliseconds("play.http.session.maxAge") mustEqual Option(sessionTimeout * 1000)
    }
  }

  "JwtSession" must {
    "read default configuration" in {
      assert(JwtSession.defaultHeader === JwtHeader(JwtAlgorithm.HS512))
      assert(configuration.algorithm === Some(JwtAlgorithm.HS512))
    }

    "init" in {
      assert(session.headerData === Json.obj("typ" -> "JWT", "alg" -> "HS512"))
      assert(session.claimData === Json.obj("exp" -> (JwtTime.now + sessionTimeout)))
      assert(!session.isEmpty) // There is the expiration date in the claim
    }

    "serialize" in {
      assert(sessionCustom.serialize === tokenCustom)
    }

    "deserialize" in {
      implicit val configuration = new JwtConfiguration(app) {
        override val options = JwtOptions(expiration = false)
      }

      assert(JwtSession.deserialize(tokenCustom) === sessionCustom)
    }
  }

  "RichResult" must {
    "access app with no user" in {
      val result1 = get(classicAction)
      val result2 = get(securedAction)

      status(result1) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result1) must not be empty
      jwtHeader(result2) must be (empty)
    }

    "fail to login" in {
      val result = post(loginAction, Json.obj("username" -> "whatever", "password" -> "wrong"))
      status(result) mustEqual BAD_REQUEST
      jwtHeader(result) mustEqual None
    }

    "login" in {
      val result = post(loginAction, Json.obj("username" -> "whatever", "password" -> "p4ssw0rd"))
      status(result) mustEqual OK
      jwtHeader(result)
        .map(JwtToken.decode(_)(jwtJson))
        .flatMap(_.claim.content.asOpt[JsObject]((JsPath \ 'user).read[JsObject])) mustEqual Some(userJson)
    }

    "access app with user" in {
      val token = JwtToken.encode(
        JwtClaim(Json.obj("user" -> userJson)),
        JwtUtils.getSigningKey(secretKey.getBytes("ISO-8859-1"), JwtAlgorithm.HS512),
        JwtAlgorithm.HS512
      ).token

      val result1 = get(classicAction, Some(token))
      val result2 = get(securedAction, Some(token))

      status(result1) mustEqual OK
      status(result2) mustEqual OK
      jwtHeader(result1)
        .map(JwtToken.decode(_)(jwtJson))
        .flatMap(_.claim.content.asOpt[JsObject]((JsPath \ 'user).read[JsObject])) mustEqual Some(userJson)
      jwtHeader(result2)
        .map(JwtToken.decode(_)(jwtJson))
        .flatMap(_.claim.content.asOpt[JsObject]((JsPath \ 'user).read[JsObject])) mustEqual Some(userJson)
    }

    "timeout session" in {
      val token = JwtToken.encode(
        JwtClaim(Json.obj("user" -> userJson), exp = Some(JwtTime.now - 30)),
        JwtUtils.getSigningKey(secretKey.getBytes("ISO-8859-1"), JwtAlgorithm.HS512),
        JwtAlgorithm.HS512
      ).token

      val result1 = get(classicAction, Some(token))
      val result2 = get(securedAction, Some(token))

      status(result1) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result1)
        .map(JwtToken.decode(_)(jwtJson))
        .flatMap(_.claim.content.asOpt[JsObject]((JsPath \ 'user).read[JsObject])) mustEqual None
      jwtHeader(result2) must be (empty)
    }

    "logout" in {
      val result = get(logoutAction)
      status(result) mustEqual OK
      jwtHeader(result) mustEqual None
    }

    "access app with no user again" in {
      val result1 = get(classicAction)
      val result2 = get(securedAction)

      status(result1) mustEqual OK
      status(result2) mustEqual UNAUTHORIZED
      jwtHeader(result1)
        .map(JwtToken.decode(_)(jwtJson))
        .flatMap(_.claim.content.asOpt[JsObject]((JsPath \ 'user).read[JsObject])) mustEqual None
      jwtHeader(result2) must be (empty)
    }
  }
}
